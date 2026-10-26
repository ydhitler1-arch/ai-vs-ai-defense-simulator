"""
simulation_engine.py
--------------------
Core orchestration engine for the AI-vs-AI Cyber Defense Simulator.
Runs episodes between the attacker AI and defender AI, manages environment
state, distributes observations, collects rewards, and coordinates all
subsystems (IDS monitor, firewall manager, metrics logger).
"""

import time
import threading
import logging
import random
import socket
import subprocess
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

from config import (
    ATTACKER_IP, TARGET_IP, DEFENDER_IP, MONITOR_IP,
    LOG_LEVEL, SIMULATION_LOG_FILE, METRICS_OUTPUT_DIR,
    SNORT_ALERT_FILE, IPTABLES_CHAIN, DVWA_URL,
    OPEN_PORTS_TARGET, ATTACKER_DETECTION_THRESHOLD,
    ENV_RESET_BETWEEN_EPISODES
)
import config

from utils import (
    setup_logger, timestamp_now, safe_execute_command,
    read_snort_alerts, parse_alert_line, flush_snort_alerts,
    check_port_open, get_active_iptables_rules, normalize_reward,
    Episode, StepResult
)
from attacker_ai import AttackerAI
from defender_ai import DefenderAI
from ids_monitor import IDSMonitor
from firewall_manager import FirewallManager
from metrics_logger import MetricsLogger

logger = setup_logger("SimulationEngine", SIMULATION_LOG_FILE, LOG_LEVEL)


# ---------------------------------------------------------------------------
# Environment State
# ---------------------------------------------------------------------------

class NetworkEnvironment:
    """
    Represents the current observable state of the virtual network.
    Both AIs receive observations derived from this shared environment.
    """

    def __init__(self):
        self.attacker_ip: str = ATTACKER_IP
        self.target_ip: str = TARGET_IP
        self.defender_ip: str = DEFENDER_IP
        self.monitor_ip: str = MONITOR_IP

        # Port visibility state (can change as firewall rules are applied)
        self.open_ports: List[int] = list(OPEN_PORTS_TARGET)
        self.blocked_ips: List[str] = []
        self.rate_limited_ips: List[str] = []

        # IDS state
        self.recent_alerts: List[Dict] = []
        self.alert_count_window: int = 0          # alerts in last step
        self.total_alerts_episode: int = 0

        # Traffic counters
        self.packets_sent_attacker: int = 0
        self.packets_blocked: int = 0

        # Session flags
        self.attacker_detected: bool = False
        self.attacker_blocked: bool = False
        self.target_compromised: bool = False
        self.services_up: Dict[str, bool] = {
            "apache": True, "mysql": True, "dvwa": True, "ssh": True
        }

        # Episode timing
        self.episode_start: float = time.time()
        self.current_step: int = 0

    def reset(self):
        """Reset environment to clean state for a new episode."""
        self.open_ports = list(OPEN_PORTS_TARGET)
        self.blocked_ips = []
        self.rate_limited_ips = []
        self.recent_alerts = []
        self.alert_count_window = 0
        self.total_alerts_episode = 0
        self.packets_sent_attacker = 0
        self.packets_blocked = 0
        self.attacker_detected = False
        self.attacker_blocked = False
        self.target_compromised = False
        self.services_up = {
            "apache": True, "mysql": True, "dvwa": True, "ssh": True
        }
        self.episode_start = time.time()
        self.current_step = 0
        logger.info("Environment state reset for new episode.")

    def get_attacker_observation(self) -> Dict[str, Any]:
        """
        Build the observation dictionary the attacker AI receives each step.
        Contains only what a real attacker could observe from outside.
        """
        return {
            "open_ports": list(self.open_ports),
            "is_detected": self.attacker_detected,
            "is_blocked": self.attacker_blocked,
            "target_compromised": self.target_compromised,
            "services_up": dict(self.services_up),
            "packets_sent": self.packets_sent_attacker,
            "step": self.current_step,
        }

    def get_defender_observation(self) -> Dict[str, Any]:
        """
        Build the observation dictionary the defender AI receives each step.
        Contains IDS alerts, traffic anomalies, blocked IP list.
        """
        return {
            "alert_count": self.alert_count_window,
            "total_alerts": self.total_alerts_episode,
            "recent_alerts": list(self.recent_alerts[-10:]),   # last 10
            "blocked_ips": list(self.blocked_ips),
            "rate_limited_ips": list(self.rate_limited_ips),
            "attacker_ip": self.attacker_ip,
            "open_ports": list(self.open_ports),
            "services_up": dict(self.services_up),
            "packets_blocked": self.packets_blocked,
            "step": self.current_step,
        }

    def apply_firewall_action(self, action: str, target_ip: str = None):
        """Update environment state to reflect a firewall action."""
        ip = target_ip or self.attacker_ip
        if action == "block_ip":
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            if ip == self.attacker_ip:
                self.attacker_blocked = True
                self.open_ports = []          # attacker can no longer see ports
        elif action == "rate_limit":
            if ip not in self.rate_limited_ips:
                self.rate_limited_ips.append(ip)
        elif action == "isolate_target":
            self.open_ports = []
            self.services_up = {k: False for k in self.services_up}
        elif action == "unblock_ip":
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
            if ip == self.attacker_ip:
                self.attacker_blocked = False
                self.open_ports = list(OPEN_PORTS_TARGET)
        elif action == "restore_services":
            self.services_up = {k: True for k in self.services_up}
            self.open_ports = list(OPEN_PORTS_TARGET)

    def register_attack(self, attack_type: str, success: bool):
        """Record the result of an attacker action in the environment."""
        self.packets_sent_attacker += 1
        if success and not self.attacker_blocked:
            if attack_type in ("sqli", "brute_force"):
                self.target_compromised = True
        if self.attacker_blocked:
            self.packets_blocked += 1

    def ingest_alerts(self, new_alerts: List[Dict]):
        """Update IDS alert state from the IDS monitor."""
        self.alert_count_window = len(new_alerts)
        self.total_alerts_episode += len(new_alerts)
        self.recent_alerts.extend(new_alerts)
        if new_alerts:
            self.attacker_detected = True
            logger.debug(f"[ENV] {len(new_alerts)} new IDS alerts ingested.")


# ---------------------------------------------------------------------------
# Reward Calculator
# ---------------------------------------------------------------------------

class RewardCalculator:
    """
    Centralised reward computation for both agents.
    All reward values are configurable here.
    """

    # Attacker rewards
    ATK_SCAN_SUCCESS       =  2.0
    ATK_SCAN_DETECTED      = -1.5
    ATK_SQLI_SUCCESS       = 10.0
    ATK_SQLI_DETECTED      = -3.0
    ATK_SQLI_BLOCKED       = -5.0
    ATK_BRUTE_SUCCESS      =  8.0
    ATK_BRUTE_DETECTED     = -2.5
    ATK_BRUTE_BLOCKED      = -4.0
    ATK_IDLE_PENALTY       = -0.5
    ATK_BLOCKED_PENALTY    = -6.0
    ATK_COMPROMISE_BONUS   = 15.0

    # Defender rewards
    DEF_DETECT_BONUS       =  5.0
    DEF_BLOCK_SUCCESS      = 10.0
    DEF_FALSE_POSITIVE     = -4.0
    DEF_MISSED_ATTACK      = -6.0
    DEF_RATE_LIMIT_HIT     =  3.0
    DEF_UNNECESSARY_ISO    = -3.0
    DEF_RESTORE_SUCCESS    =  2.0
    DEF_IDLE_WHEN_ATTACK   = -3.0
    DEF_LOG_ONLY           =  0.5

    @staticmethod
    def attacker_reward(action: str, env: NetworkEnvironment,
                        attack_success: bool) -> float:
        reward = 0.0

        if env.attacker_blocked:
            return RewardCalculator.ATK_BLOCKED_PENALTY

        if action == "scan":
            if attack_success:
                reward += RewardCalculator.ATK_SCAN_SUCCESS
            if env.attacker_detected:
                reward += RewardCalculator.ATK_SCAN_DETECTED

        elif action == "sqli":
            if attack_success:
                reward += RewardCalculator.ATK_SQLI_SUCCESS
                if env.target_compromised:
                    reward += RewardCalculator.ATK_COMPROMISE_BONUS
            else:
                reward += RewardCalculator.ATK_SQLI_DETECTED
            if env.attacker_blocked:
                reward += RewardCalculator.ATK_SQLI_BLOCKED

        elif action == "brute_force":
            if attack_success:
                reward += RewardCalculator.ATK_BRUTE_SUCCESS
            else:
                reward += RewardCalculator.ATK_BRUTE_DETECTED
            if env.attacker_blocked:
                reward += RewardCalculator.ATK_BRUTE_BLOCKED

        elif action == "idle":
            reward += RewardCalculator.ATK_IDLE_PENALTY

        return normalize_reward(reward, -20.0, 30.0)

    @staticmethod
    def defender_reward(action: str, env: NetworkEnvironment,
                        was_attack_happening: bool,
                        correctly_blocked: bool) -> float:
        reward = 0.0

        if was_attack_happening:
            if action == "block_ip" and correctly_blocked:
                reward += RewardCalculator.DEF_BLOCK_SUCCESS
            elif action == "block_ip" and not correctly_blocked:
                reward += RewardCalculator.DEF_FALSE_POSITIVE
            elif action == "rate_limit" and env.alert_count_window > 0:
                reward += RewardCalculator.DEF_RATE_LIMIT_HIT
            elif action == "log_only":
                reward += RewardCalculator.DEF_LOG_ONLY
                if env.total_alerts_episode > ATTACKER_DETECTION_THRESHOLD:
                    reward += RewardCalculator.DEF_IDLE_WHEN_ATTACK
            elif action == "isolate_target":
                if env.target_compromised:
                    reward += RewardCalculator.DEF_BLOCK_SUCCESS
                else:
                    reward += RewardCalculator.DEF_UNNECESSARY_ISO
        else:
            # No attack happening
            if action == "block_ip":
                reward += RewardCalculator.DEF_FALSE_POSITIVE
            elif action == "isolate_target":
                reward += RewardCalculator.DEF_UNNECESSARY_ISO
            elif action == "restore_services":
                reward += RewardCalculator.DEF_RESTORE_SUCCESS
            else:
                reward += 0.2   # small idle reward when quiet

        if env.attacker_detected and not env.attacker_blocked:
            reward += RewardCalculator.DEF_DETECT_BONUS * 0.5

        return normalize_reward(reward, -15.0, 20.0)


# ---------------------------------------------------------------------------
# Simulation Engine
# ---------------------------------------------------------------------------

class SimulationEngine:
    """
    Main simulation orchestrator.
    Manages the full episode lifecycle:
      1. Reset environment
      2. For each step: get attacker action → execute → get IDS alerts →
         get defender action → execute → compute rewards → update Q-tables
      3. Log metrics after each episode
      4. Save models periodically
    """

    def __init__(self):
        logger.info("=" * 60)
        logger.info("  AI-vs-AI Cyber Defense Simulator — Engine Starting")
        logger.info("=" * 60)

        # Core subsystems
        self.env = NetworkEnvironment()
        self.attacker = AttackerAI(TARGET_IP)
        self.defender = DefenderAI()
        self.ids_monitor = IDSMonitor(alert_file=SNORT_ALERT_FILE)
        self.firewall = FirewallManager(chain=IPTABLES_CHAIN)
        self.metrics = MetricsLogger(output_dir=METRICS_OUTPUT_DIR)
        self.reward_calc = RewardCalculator()

        # Simulation state
        self.current_episode: int = 0
        self.is_running: bool = False
        self._stop_event = threading.Event()

        # Live statistics (reset per episode)
        self._ep_attacker_rewards: List[float] = []
        self._ep_defender_rewards: List[float] = []
        self._ep_attack_successes: int = 0
        self._ep_attack_attempts: int = 0
        self._ep_detections: int = 0
        self._ep_blocks: int = 0
        self._ep_false_positives: int = 0
        self._ep_response_times: List[float] = []

        logger.info("All subsystems initialised successfully.")

    # ------------------------------------------------------------------
    # Public control methods
    # ------------------------------------------------------------------

    def run(self):
        """Start the full simulation for config.TOTAL_EPISODES episodes."""
        self.is_running = True
        logger.info(f"Starting simulation: {config.TOTAL_EPISODES} episodes, "
                    f"{config.STEPS_PER_EPISODE} steps each.")

        try:
            # Without this the alert tailer never runs and the defender
            # never sees any IDS alert (detection accuracy stays at 0%).
            self.ids_monitor.start()
            for ep in range(1, config.TOTAL_EPISODES + 1):
                if self._stop_event.is_set():
                    logger.info("Stop signal received — halting simulation.")
                    break
                self.current_episode = ep
                self._run_episode(ep)

        except KeyboardInterrupt:
            logger.warning("KeyboardInterrupt — saving state and exiting.")
        finally:
            self._shutdown()

    def stop(self):
        """Signal the simulation to stop after the current episode."""
        self._stop_event.set()
        logger.info("Stop requested — will halt after current episode.")

    # ------------------------------------------------------------------
    # Episode lifecycle
    # ------------------------------------------------------------------

    def _run_episode(self, episode_num: int):
        logger.info(f"\n{'='*55}")
        logger.info(f"  EPISODE {episode_num:04d} / {config.TOTAL_EPISODES:04d}  "
                    f"[{timestamp_now()}]")
        logger.info(f"{'='*55}")

        # Reset environment and per-episode stats
        if ENV_RESET_BETWEEN_EPISODES:
            self.env.reset()
            self.firewall.flush_episode_rules()
            flush_snort_alerts(SNORT_ALERT_FILE)

        self._reset_episode_stats()
        episode_obj = Episode(episode_num)

        # Decay exploration rates
        self.attacker.decay_epsilon()
        self.defender.decay_epsilon()

        attack_was_happening = False

        for step in range(1, config.STEPS_PER_EPISODE + 1):
            if self._stop_event.is_set():
                break

            self.env.current_step = step
            step_start = time.time()

            # ── 1. Attacker acts ──────────────────────────────────────
            atk_obs = self.env.get_attacker_observation()
            atk_action = self.attacker.choose_action(atk_obs)
            atk_success, atk_info = self._execute_attack(atk_action)
            self.env.register_attack(atk_action, atk_success)
            attack_was_happening = (atk_action != "idle")

            if atk_success:
                self._ep_attack_successes += 1
            self._ep_attack_attempts += 1

            logger.info(f"  [Step {step:03d}] ATK={str(atk_action):<12s} "

                        f"success={atk_success}  blocked={self.env.attacker_blocked}")

            # ── 2. IDS ingests traffic ────────────────────────────────
            time.sleep(0.05)   # tiny delay to let Snort catch up
            new_alerts = self.ids_monitor.poll_new_alerts()
            self.env.ingest_alerts(new_alerts)
            if new_alerts:
                self._ep_detections += 1

            # ── 3. Defender acts ──────────────────────────────────────
            def_obs = self.env.get_defender_observation()
            def_action = self.defender.choose_action(def_obs)
            correctly_blocked = self._execute_defense(def_action)

            if def_action == "block_ip":
                if correctly_blocked:
                    self._ep_blocks += 1
                else:
                    self._ep_false_positives += 1

            response_time = time.time() - step_start
            self._ep_response_times.append(response_time)

            logger.info(f"            DEF={str(def_action):<12s} "
                        f"correct={correctly_blocked}  "
                        f"resp={response_time:.3f}s")

            # ── 4. Compute rewards ────────────────────────────────────
            atk_reward = self.reward_calc.attacker_reward(
                atk_action, self.env, atk_success)
            def_reward = self.reward_calc.defender_reward(
                def_action, self.env, attack_was_happening, correctly_blocked)

            self._ep_attacker_rewards.append(atk_reward)
            self._ep_defender_rewards.append(def_reward)

            # ── 5. Update Q-tables ────────────────────────────────────
            atk_next_obs = self.env.get_attacker_observation()
            def_next_obs = self.env.get_defender_observation()

            self.attacker.update_q_table(
                atk_obs, atk_action, atk_reward, atk_next_obs)
            self.defender.update_q_table(
                def_obs, def_action, def_reward, def_next_obs)

            # ── 6. Record step ────────────────────────────────────────
            step_result = StepResult(
                step=step,
                atk_action=atk_action,
                atk_success=atk_success,
                atk_reward=atk_reward,
                def_action=def_action,
                def_correct=correctly_blocked,
                def_reward=def_reward,
                alert_count=self.env.alert_count_window,
                response_time=response_time,
            )
            episode_obj.add_step(step_result)
            # Log step metrics
            self.metrics.log_step(self.current_episode, {
                "step": step,
                "atk_action": atk_action,
                "atk_success": atk_success,
                "atk_reward": atk_reward,
                "def_action": def_action,
                "def_correct": correctly_blocked,
                "def_reward": def_reward,
                "alert_count": self.env.alert_count_window,
                "response_time": response_time,
            })

            # ── 7. Early termination check ────────────────────────────
            if self._should_terminate_early():
                logger.info(f"  Early termination at step {step}.")
                break

            time.sleep(config.STEP_DELAY_SECONDS)

        # ── End of episode: log metrics ───────────────────────────────
        self._finalise_episode(episode_obj)

    # ------------------------------------------------------------------
    # Attack execution
    # ------------------------------------------------------------------

    def _execute_attack(self, action: str) -> Tuple[bool, Dict]:
        """
        Execute the chosen attacker action against the target VM.
        Returns (success, info_dict).
        """
        if self.env.attacker_blocked:
            logger.debug(f"Attack '{action}' skipped — attacker is blocked.")
            return False, {"reason": "blocked"}

        info = {"action": action, "timestamp": timestamp_now()}

        if action == "scan":
            return self._do_nmap_scan(info)
        elif action == "sqli":
            return self._do_sqli(info)
        elif action == "brute_force":
            return self._do_brute_force(info)
        elif action == "idle":
            logger.debug("Attacker is idle this step.")
            return False, {"reason": "idle"}
        elif action == "ddos":
            return self._do_ddos(info)

        else:
            logger.warning(f"Unknown attack action: {action}")
            return False, {"reason": "unknown_action"}

    def _do_nmap_scan(self, info: Dict) -> Tuple[bool, Dict]:
        """Run a targeted Nmap scan from attacker to target."""
        # Simulate scan: check if common ports are reachable
        reachable_ports = []
        for port in self.env.open_ports:
            if check_port_open(TARGET_IP, port, timeout=1.0):
                reachable_ports.append(port)

        success = len(reachable_ports) > 0
        info.update({"reachable_ports": reachable_ports, "success": success})

        if success:
            # Attacker now knows which ports are open
            self.env.open_ports = reachable_ports
            logger.debug(f"Nmap scan found open ports: {reachable_ports}")
        else:
            logger.debug("Nmap scan found no open ports.")

        # Simulate network noise that Snort might catch
        self._simulate_network_event("scan", success)
        return success, info

    def _do_sqli(self, info: Dict) -> Tuple[bool, Dict]:
        """Simulate an SQL injection attack against DVWA."""
        if not self.env.services_up.get("dvwa", False):
            logger.debug("SQLi skipped — DVWA service is down.")
            return False, {"reason": "service_down"}

        # Check if HTTP port is reachable
        http_open = check_port_open(TARGET_IP, 80, timeout=2.0)
        if not http_open:
            return False, {"reason": "port_closed"}

        # Simulate probabilistic SQLi success (harder if detected)
        base_prob = 0.65
        if self.env.attacker_detected:
            base_prob -= 0.20
        if self.env.rate_limited_ips:
            base_prob -= 0.15

        success = random.random() < max(base_prob, 0.05)
        info.update({"success": success, "target_url": DVWA_URL})
        self._simulate_network_event("sqli", success)
        return success, info

    def _do_brute_force(self, info: Dict) -> Tuple[bool, Dict]:
        """Simulate SSH brute force attack."""
        ssh_open = check_port_open(TARGET_IP, 22, timeout=2.0)
        if not ssh_open:
            return False, {"reason": "ssh_closed"}

        base_prob = 0.35
        if self.env.attacker_detected:
            base_prob -= 0.15
        if self.env.attacker_blocked:
            return False, {"reason": "blocked"}

        success = random.random() < max(base_prob, 0.02)
        info.update({"success": success, "target_port": 22})
        self._simulate_network_event("brute_force", success)
        return success, info

    def _simulate_network_event(self, attack_type: str, success: bool):
        """
        Inject a synthetic Snort alert entry to simulate IDS detection.
        In a real deployment this is replaced by actual Snort output.
        """
        alert_prob = {
            "scan": 0.60,
            "sqli": 0.75,
            "brute_force": 0.70,
            "ddos": 0.80,
        }.get(attack_type, 0.5)

        if random.random() < alert_prob:
            # Same one-line layout Snort's "fast" alert mode writes, so
            # IDSMonitor's parser can read it.
            alert_line = (
                f'{datetime.now().strftime("%m/%d-%H:%M:%S.%f")}  '
                f'[**] [1:1000001:1] Simulated {attack_type.upper()} Alert [**] '
                f'[Priority: 2] {{TCP}} {ATTACKER_IP}:54321 -> {TARGET_IP}:80\n'
            )
            # Append to Snort alert file so IDSMonitor picks it up
            try:
                with open(SNORT_ALERT_FILE, "a") as f:
                    f.write(alert_line)
            except IOError as e:
                logger.warning(f"Could not write simulated alert: {e}")

    def _do_ddos(self, info: Dict) -> Tuple[bool, Dict]:
        """Simulate DDoS attack against target"""
        http_open = check_port_open(TARGET_IP, 80, timeout=2.0)
        if not http_open:
            return False, {"reason": "port_closed"}

        base_prob = 0.4
        if self.env.attacker_blocked:
            return False, {"reason": "blocked"}
        if self.env.rate_limited_ips:
            base_prob -= 0.2

        success = random.random() < max(base_prob, 0.05)
        info.update({"success": success, "target_port": 80})
        self._simulate_network_event("ddos", success)
        return success, info


    # ------------------------------------------------------------------
    # Defense execution
    # ------------------------------------------------------------------

    def _execute_defense(self, action: str) -> bool:
        """
        Execute the chosen defender action via FirewallManager.
        Returns True if the action was genuinely beneficial (correctly applied).
        """
        attack_happening = self.env.alert_count_window > 0 or self.env.attacker_detected

        if action == "block_ip":
            if attack_happening:
                result = self.firewall.block_ip(self.env.attacker_ip)
                if result:
                    self.env.apply_firewall_action("block_ip", self.env.attacker_ip)
                return result and attack_happening
            else:
                # False positive — block applied unnecessarily
                self.firewall.block_ip(self.env.attacker_ip)
                return False

        elif action == "rate_limit":
            result = self.firewall.rate_limit_ip(self.env.attacker_ip)
            self.env.apply_firewall_action("rate_limit", self.env.attacker_ip)
            return result and attack_happening

        elif action == "isolate_target":
            result = self.firewall.isolate_target(TARGET_IP, allow_management_ip=DEFENDER_IP)
            self.env.apply_firewall_action("isolate_target")
            return result and self.env.target_compromised

        elif action == "restore_services":
            result = self.firewall.restore_rules(self.env.attacker_ip)
            self.env.apply_firewall_action("restore_services")
            return result

        elif action == "log_only":
            logger.info(f"  [DEF] Logging alert — no active block applied.")
            return False  # not actively defended

        else:
            logger.warning(f"Unknown defense action: {action}")
            return False

    # ------------------------------------------------------------------
    # Episode finalisation
    # ------------------------------------------------------------------

    def _finalise_episode(self, episode: Episode):
        """Compute episode metrics and hand off to MetricsLogger."""
        total_steps = episode.total_steps()
        total_attempts = max(self._ep_attack_attempts, 1)

        attack_success_rate = self._ep_attack_successes / total_attempts
        detection_accuracy  = (
            self._ep_detections / total_attempts
            if total_attempts else 0.0
        )
        false_positive_rate = (
            self._ep_false_positives / max(self._ep_blocks + self._ep_false_positives, 1)
        )
        avg_response_time = (
            sum(self._ep_response_times) / len(self._ep_response_times)
            if self._ep_response_times else 0.0
        )
        avg_atk_reward = (
            sum(self._ep_attacker_rewards) / len(self._ep_attacker_rewards)
            if self._ep_attacker_rewards else 0.0
        )
        avg_def_reward = (
            sum(self._ep_defender_rewards) / len(self._ep_defender_rewards)
            if self._ep_defender_rewards else 0.0
        )

        episode_summary = {
            "episode": self.current_episode,
            "total_steps": total_steps,
            "attack_success_rate": round(attack_success_rate, 4),
            "detection_accuracy": round(detection_accuracy, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "avg_response_time_s": round(avg_response_time, 4),
            "avg_attacker_reward": round(avg_atk_reward, 4),
            "avg_defender_reward": round(avg_def_reward, 4),
            "total_blocks": self._ep_blocks,
            "total_false_positives": self._ep_false_positives,
            "attacker_epsilon": round(self.attacker.epsilon, 4),
            "defender_epsilon": round(self.defender.epsilon, 4),
            "target_compromised": self.env.target_compromised,
        }

        self.metrics.log_episode(episode_summary)
        episode.set_summary(episode_summary)

        logger.info(
            f"\n  ── Episode {self.current_episode} Summary ──\n"
            f"  Attack success rate : {attack_success_rate:.2%}\n"
            f"  Detection accuracy  : {detection_accuracy:.2%}\n"
            f"  False positive rate : {false_positive_rate:.2%}\n"
            f"  Avg response time   : {avg_response_time:.3f}s\n"
            f"  Avg ATK reward      : {avg_atk_reward:.3f}\n"
            f"  Avg DEF reward      : {avg_def_reward:.3f}\n"
            f"  Target compromised  : {self.env.target_compromised}\n"
        )

        # Periodically save AI models
        if self.current_episode % 10 == 0:
            self.attacker.save_model()
            self.defender.save_model()
            logger.info(f"  AI models saved at episode {self.current_episode}.")

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _reset_episode_stats(self):
        self._ep_attacker_rewards = []
        self._ep_defender_rewards = []
        self._ep_attack_successes = 0
        self._ep_attack_attempts  = 0
        self._ep_detections       = 0
        self._ep_blocks           = 0
        self._ep_false_positives  = 0
        self._ep_response_times   = []

    def _should_terminate_early(self) -> bool:
        """Terminate episode early under extreme conditions."""
        # If attacker is fully blocked and target not compromised, episode is done
        if self.env.attacker_blocked and not self.env.target_compromised:
            if self.env.current_step > config.STEPS_PER_EPISODE // 2:
                return True
        return False

    def _shutdown(self):
        """Clean up all resources at end of simulation."""
        logger.info("\nSimulation complete. Shutting down subsystems...")
        self.ids_monitor.stop()
        self.firewall.flush_all_episode_rules()
        self.metrics.finalise()
        self.attacker.save_model()
        self.defender.save_model()
        self.is_running = False
        logger.info("All subsystems shut down cleanly.")
        logger.info("="*60)


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    engine = SimulationEngine()
    engine.run()
