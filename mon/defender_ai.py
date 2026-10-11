"""
defender_ai.py
==============
Reinforcement-Learning based Defender Agent for the AI-vs-AI Cyber Defense Simulator.

The defender observes the network environment (IDS alerts, traffic rate, suspicious IPs)
and selects one of four actions:
    0 - LOG      : Record the event, take no active action
    1 - RATE_LIMIT: Throttle traffic from the suspicious IP via iptables
    2 - BLOCK    : Completely block the attacker IP via iptables
    3 - ISOLATE  : Isolate the target VM (block all inbound except management)

Reward structure:
    +10  : Successfully blocked a real attack
    +5   : Rate-limiting slowed down a real attack
    +2   : Correctly logging a benign event
    -5   : False positive – blocked/isolated a legitimate source
    -8   : Missed an attack (attacker succeeded despite defender action)
    -3   : Unnecessary isolation (no real attack happening)
"""

import os
import json
import time
import random
import logging
import numpy as np
from datetime import datetime
from collections import defaultdict

# ── project-local imports ──────────────────────────────────────────────────
from config import (
    DEFENDER_IP, TARGET_IP, ATTACKER_IP,
    DEFENDER_LEARNING_RATE, DEFENDER_DISCOUNT_FACTOR,
    DEFENDER_EPSILON_START, DEFENDER_EPSILON_END, DEFENDER_EPSILON_DECAY,
    DEFENDER_MODEL_PATH, LOG_DIR
)
from firewall_manager import FirewallManager
from ids_monitor import IDSMonitor
from utils import get_logger, save_json, load_json

# ──────────────────────────────────────────────────────────────────────────
logger = get_logger("DefenderAI")


# ═══════════════════════════════════════════════════════════════════════════
# STATE ENCODER
# ═══════════════════════════════════════════════════════════════════════════
class DefenderStateEncoder:
    """
    Converts raw defender observations into a discrete state tuple
    suitable for a Q-table lookup.

    Observation space:
        alert_count        : number of IDS alerts in the last window   (0-3 buckets)
        alert_severity     : max severity seen                          (0=none,1=low,2=med,3=high)
        traffic_rate       : packets-per-second from suspicious IP      (0-3 buckets)
        attacker_blocked   : is the attacker already blocked?           (0/1)
        target_reachable   : is the target still reachable?             (0/1)
        repeated_source    : same source IP seen ≥3 times in window?    (0/1)
    """

    # bucket boundaries
    ALERT_BUCKETS   = [0, 3, 8]          # 0 alerts | 1-3 | 4-8 | 9+
    TRAFFIC_BUCKETS = [0, 50, 200]       # 0 pps   | 1-50 | 51-200 | 201+

    def encode(self, obs: dict) -> tuple:
        alert_count      = self._bucket(obs.get("alert_count", 0),      self.ALERT_BUCKETS)
        alert_severity   = min(int(obs.get("alert_severity", 0)), 3)
        traffic_rate     = self._bucket(obs.get("traffic_rate_pps", 0), self.TRAFFIC_BUCKETS)
        attacker_blocked = int(bool(obs.get("attacker_blocked", False)))
        target_reachable = int(bool(obs.get("target_reachable", True)))
        repeated_source  = int(bool(obs.get("repeated_source", False)))

        return (alert_count, alert_severity, traffic_rate,
                attacker_blocked, target_reachable, repeated_source)

    @staticmethod
    def _bucket(value: float, boundaries: list) -> int:
        for i, b in enumerate(reversed(boundaries)):
            if value > b:
                return len(boundaries) - i
        return 0

    @property
    def state_space_size(self) -> int:
        # 4 * 4 * 4 * 2 * 2 * 2
        return 4 * 4 * 4 * 2 * 2 * 2


# ═══════════════════════════════════════════════════════════════════════════
# DEFENDER ACTIONS
# ═══════════════════════════════════════════════════════════════════════════
class DefenderActions:
    LOG        = 0
    RATE_LIMIT = 1
    BLOCK      = 2
    ISOLATE    = 3

    NAMES = {0: "LOG", 1: "RATE_LIMIT", 2: "BLOCK", 3: "ISOLATE"}
    ALL   = [LOG, RATE_LIMIT, BLOCK, ISOLATE]

    @staticmethod
    def name(action_id: int) -> str:
        return DefenderActions.NAMES.get(action_id, "UNKNOWN")


# ═══════════════════════════════════════════════════════════════════════════
# Q-TABLE (persisted as JSON)
# ═══════════════════════════════════════════════════════════════════════════
class QTable:
    def __init__(self, n_actions: int = 4, default_value: float = 0.0):
        self.n_actions     = n_actions
        self.default_value = default_value
        self._table: dict  = {}

    # ── serialisation ──────────────────────────────────────────────────────
    def _key(self, state: tuple) -> str:
        return json.dumps(state)

    def get(self, state: tuple, action: int) -> float:
        row = self._table.get(self._key(state))
        if row is None:
            return self.default_value
        return row.get(str(action), self.default_value)

    def set(self, state: tuple, action: int, value: float):
        k = self._key(state)
        if k not in self._table:
            self._table[k] = {str(a): self.default_value for a in range(self.n_actions)}
        self._table[k][str(action)] = value

    def best_action(self, state: tuple) -> int:
        k = self._key(state)
        row = self._table.get(k)
        if not row:
            return random.choice(range(self.n_actions))
        best = max(row, key=row.get)
        return int(best)

    def best_value(self, state: tuple) -> float:
        k = self._key(state)
        row = self._table.get(k)
        if not row:
            return self.default_value
        return max(row.values())

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(self._table, f, indent=2)
        logger.info(f"Q-table saved → {path}  ({len(self._table)} states)")

    def load(self, path: str):
        if not os.path.exists(path):
            logger.warning(f"No Q-table found at {path}. Starting fresh.")
            return
        with open(path, "r") as f:
            self._table = json.load(f)
        logger.info(f"Q-table loaded ← {path}  ({len(self._table)} states)")

    def __len__(self):
        return len(self._table)


# ═══════════════════════════════════════════════════════════════════════════
# REWARD CALCULATOR
# ═══════════════════════════════════════════════════════════════════════════
class RewardCalculator:
    """Stateless reward function for the defender."""

    # reward constants
    R_BLOCK_SUCCESS      =  10.0
    R_RATE_LIMIT_SUCCESS =   5.0
    R_CORRECT_LOG        =   2.0
    R_FALSE_POSITIVE     =  -5.0
    R_MISSED_ATTACK      =  -8.0
    R_WRONG_ISOLATE      =  -3.0
    R_ISOLATE_SUCCESS    =  12.0

    def calculate(self, action: int, attack_actually_happened: bool,
                  attack_succeeded: bool, legitimate_traffic: bool) -> tuple[float, str]:
        """
        Returns (reward, reason_string).
        """
        a = action

        if attack_actually_happened:
            if a == DefenderActions.BLOCK:
                if not attack_succeeded:
                    return self.R_BLOCK_SUCCESS, "Attacker blocked successfully"
                else:
                    return self.R_MISSED_ATTACK * 0.5, "Block attempted but attack still succeeded"
            elif a == DefenderActions.RATE_LIMIT:
                if not attack_succeeded:
                    return self.R_RATE_LIMIT_SUCCESS, "Rate-limit slowed attack successfully"
                else:
                    return self.R_MISSED_ATTACK, "Rate-limit insufficient, attack succeeded"
            elif a == DefenderActions.ISOLATE:
                if not attack_succeeded:
                    return self.R_ISOLATE_SUCCESS, "Isolation prevented attack"
                else:
                    return self.R_MISSED_ATTACK, "Isolation failed to stop attack"
            else:  # LOG
                if attack_succeeded:
                    return self.R_MISSED_ATTACK, "Attack succeeded – only logged"
                else:
                    return 0.0, "Logged attack that didn't succeed anyway"
        else:
            # no real attack
            if a == DefenderActions.LOG:
                if legitimate_traffic:
                    return self.R_CORRECT_LOG, "Correctly logged benign traffic"
                else:
                    return 0.5, "Logged (no significant traffic)"
            elif a in (DefenderActions.BLOCK, DefenderActions.RATE_LIMIT):
                if legitimate_traffic:
                    return self.R_FALSE_POSITIVE, "False positive – blocked legitimate source"
                else:
                    return -1.0, "Unnecessary block (no traffic)"
            elif a == DefenderActions.ISOLATE:
                return self.R_WRONG_ISOLATE, "Unnecessary isolation (no real attack)"

        return 0.0, "No reward condition matched"


# ═══════════════════════════════════════════════════════════════════════════
# MAIN DEFENDER AI CLASS
# ═══════════════════════════════════════════════════════════════════════════
class DefenderAI:
    """
    Full Q-learning defender agent.

    Usage (from simulation engine):
        defender = DefenderAI()
        defender.load_model()

        obs    = defender.observe()           # gather live state
        action = defender.choose_action(obs)  # ε-greedy selection
        result = defender.execute_action(action, target_ip)
        reward = defender.receive_reward(action, attack_happened, attack_succeeded, legit)
        defender.update_q(obs, action, reward, next_obs)
        defender.decay_epsilon()
    """

    def __init__(self):
        self.encoder   = DefenderStateEncoder()
        self.qtable    = QTable(n_actions=len(DefenderActions.ALL))
        self.firewall  = FirewallManager()
        self.ids       = IDSMonitor()
        self.reward_fn = RewardCalculator()

        # RL hyper-parameters (from config)
        self.lr           = DEFENDER_LEARNING_RATE
        self.gamma        = DEFENDER_DISCOUNT_FACTOR
        self.epsilon      = DEFENDER_EPSILON_START
        self.epsilon_min  = DEFENDER_EPSILON_END
        self.epsilon_decay= DEFENDER_EPSILON_DECAY

        # Episode tracking
        self.episode           = 0
        self.step              = 0
        self.total_reward      = 0.0
        self.episode_rewards   = []
        self.action_history    = []
        self.blocked_ips: set  = set()

        # Observation window
        self._alert_window: list = []
        self._window_seconds     = 30

        logger.info("DefenderAI initialised.")

    # ──────────────────────────────────────────────────────────────────────
    # MODEL PERSISTENCE
    # ──────────────────────────────────────────────────────────────────────
    def load_model(self):
        self.qtable.load(DEFENDER_MODEL_PATH)

    def save_model(self):
        self.qtable.save(DEFENDER_MODEL_PATH)

    # ──────────────────────────────────────────────────────────────────────
    # OBSERVATION
    # ──────────────────────────────────────────────────────────────────────
    def observe(self, suspicious_ip: str = None) -> dict:
        """
        Collect a live observation dict from IDS alerts, firewall state,
        and basic reachability check.
        """
        suspicious_ip = suspicious_ip or ATTACKER_IP

        # Pull recent alerts from IDS
        alerts = self.ids.get_recent_alerts(seconds=self._window_seconds)

        # Filter for alerts involving the suspicious IP
        ip_alerts = [a for a in alerts if suspicious_ip in a.get("src_ip", "")]

        alert_count    = len(ip_alerts)
        alert_severity = max((a.get("severity", 0) for a in ip_alerts), default=0)
        traffic_rate   = self.ids.get_traffic_rate(suspicious_ip)
        repeated       = alert_count >= 3
        already_blocked= suspicious_ip in self.blocked_ips
        target_up      = self._ping_target()

        obs = {
            "alert_count"    : alert_count,
            "alert_severity" : alert_severity,
            "traffic_rate_pps": traffic_rate,
            "repeated_source": repeated,
            "attacker_blocked": already_blocked,
            "target_reachable": target_up,
            "suspicious_ip"  : suspicious_ip,
            "raw_alerts"     : ip_alerts,
            "timestamp"      : datetime.now().isoformat(),
        }

        logger.debug(f"Observation: alerts={alert_count}, sev={alert_severity}, "
                     f"pps={traffic_rate:.1f}, blocked={already_blocked}, target_up={target_up}")
        return obs

    def _ping_target(self) -> bool:
        """Returns True if the target VM responds to ping."""
        response = os.system(f"ping -c 1 -W 1 {TARGET_IP} > /dev/null 2>&1")
        return response == 0

    # ──────────────────────────────────────────────────────────────────────
    # ACTION SELECTION  (ε-greedy)
    # ──────────────────────────────────────────────────────────────────────
    def choose_action(self, obs: dict) -> int:
        state = self.encoder.encode(obs)

        if random.random() < self.epsilon:
            action = random.choice(DefenderActions.ALL)
            logger.debug(f"ε-greedy EXPLORE → {DefenderActions.name(action)}")
        else:
            action = self.qtable.best_action(state)
            logger.debug(f"EXPLOIT → {DefenderActions.name(action)}")

        return action

    # ──────────────────────────────────────────────────────────────────────
    # ACTION EXECUTION
    # ──────────────────────────────────────────────────────────────────────
    def execute_action(self, action: int, target_ip: str = None,
                       suspicious_ip: str = None) -> dict:
        """
        Execute the chosen action using FirewallManager.
        Returns a result dict.
        """
        suspicious_ip = suspicious_ip or ATTACKER_IP
        target_ip     = target_ip     or TARGET_IP
        result        = {"action": action, "action_name": DefenderActions.name(action),
                         "success": False, "message": ""}

        logger.info(f"[Step {self.step}] Executing: {DefenderActions.name(action)} "
                    f"on {suspicious_ip}")

        try:
            if action == DefenderActions.LOG:
                result["success"] = True
                result["message"] = "Event logged; no firewall change."
                logger.info(f"  → LOGGED suspicious activity from {suspicious_ip}")

            elif action == DefenderActions.RATE_LIMIT:
                ok = self.firewall.rate_limit_ip(suspicious_ip, rate="30/min", burst=50)
                result["success"] = ok
                result["message"] = f"Rate-limit applied to {suspicious_ip}" if ok else "Rate-limit failed"
                if ok:
                    logger.info(f"  → RATE-LIMITED {suspicious_ip}")

            elif action == DefenderActions.BLOCK:
                ok = self.firewall.block_ip(suspicious_ip)
                result["success"] = ok
                result["message"] = f"Blocked {suspicious_ip}" if ok else "Block failed"
                if ok:
                    self.blocked_ips.add(suspicious_ip)
                    logger.warning(f"  → BLOCKED {suspicious_ip}")

            elif action == DefenderActions.ISOLATE:
                ok = self.firewall.isolate_target(target_ip, allow_management_ip=DEFENDER_IP)
                result["success"] = ok
                result["message"] = f"Isolated {target_ip}" if ok else "Isolation failed"
                if ok:
                    logger.warning(f"  → ISOLATED target {target_ip}")

        except Exception as exc:
            result["message"] = f"Exception during execution: {exc}"
            logger.error(f"Action execution error: {exc}", exc_info=True)

        self.action_history.append({
            "episode"    : self.episode,
            "step"       : self.step,
            "action"     : action,
            "action_name": DefenderActions.name(action),
            "target_ip"  : target_ip,
            "suspicious" : suspicious_ip,
            "success"    : result["success"],
            "timestamp"  : datetime.now().isoformat(),
        })

        self.step += 1
        return result

    # ──────────────────────────────────────────────────────────────────────
    # REWARD + Q-UPDATE
    # ──────────────────────────────────────────────────────────────────────
    def receive_reward(self, action: int,
                       attack_actually_happened: bool,
                       attack_succeeded: bool,
                       legitimate_traffic: bool = False) -> float:
        reward, reason = self.reward_fn.calculate(
            action, attack_actually_happened, attack_succeeded, legitimate_traffic
        )
        self.total_reward += reward
        logger.info(f"  Reward: {reward:+.1f}  ({reason})")
        return reward

    def update_q(self, obs: dict, action: int,
                 reward: float, next_obs: dict):
        """Standard Q-learning (Bellman) update."""
        state      = self.encoder.encode(obs)
        next_state = self.encoder.encode(next_obs)

        old_q    = self.qtable.get(state, action)
        next_max = self.qtable.best_value(next_state)

        new_q = old_q + self.lr * (reward + self.gamma * next_max - old_q)
        self.qtable.set(state, action, new_q)

        logger.debug(f"Q-update: state={state} action={action} "
                     f"Q:{old_q:.3f}→{new_q:.3f}")

    # ──────────────────────────────────────────────────────────────────────
    # EPSILON DECAY
    # ──────────────────────────────────────────────────────────────────────
    def decay_epsilon(self):
        if self.epsilon > self.epsilon_min:
            self.epsilon = max(self.epsilon_min,
                               self.epsilon * self.epsilon_decay)
        logger.debug(f"ε decayed → {self.epsilon:.4f}")

    # ──────────────────────────────────────────────────────────────────────
    # EPISODE MANAGEMENT
    # ──────────────────────────────────────────────────────────────────────
    def start_episode(self):
        self.episode += 1
        self.step         = 0
        self.total_reward = 0.0
        logger.info(f"── Defender Episode {self.episode} started ──")

    def end_episode(self) -> dict:
        summary = {
            "episode"      : self.episode,
            "total_reward" : round(self.total_reward, 3),
            "steps"        : self.step,
            "epsilon"      : round(self.epsilon, 4),
            "q_table_size" : len(self.qtable),
            "blocked_ips"  : list(self.blocked_ips),
            "timestamp"    : datetime.now().isoformat(),
        }
        self.episode_rewards.append(self.total_reward)
        self.save_model()
        self._save_episode_log(summary)
        logger.info(f"── Episode {self.episode} ended | reward={self.total_reward:.2f} ──")
        return summary

    def _save_episode_log(self, summary: dict):
        path = os.path.join(LOG_DIR, f"defender_episode_{self.episode:04d}.json")
        save_json(summary, path)

    # ──────────────────────────────────────────────────────────────────────
    # UTILITY
    # ──────────────────────────────────────────────────────────────────────
    def unblock_all(self):
        """Call at the start of a fresh simulation run to reset firewall state."""
        for ip in list(self.blocked_ips):
            self.firewall.unblock_ip(ip)
        self.blocked_ips.clear()
        self.firewall.clear_rate_limits()
        logger.info("All blocks and rate-limits cleared.")

    def get_stats(self) -> dict:
        actions = [h["action_name"] for h in self.action_history]
        counts  = {name: actions.count(name) for name in DefenderActions.NAMES.values()}
        return {
            "episodes"          : self.episode,
            "total_steps"       : len(self.action_history),
            "action_distribution": counts,
            "epsilon"           : round(self.epsilon, 4),
            "q_table_states"    : len(self.qtable),
            "avg_episode_reward": round(
                sum(self.episode_rewards) / max(len(self.episode_rewards), 1), 3
            ),
        }

    def choose_action(self, observation):
        """Choose action and return as string name for simulation engine"""
        action_int = self._choose_action_int(observation)
        action_map = {
            0: 'log_only',
            1: 'rate_limit',
            2: 'block_ip',
            3: 'isolate_target'
        }
        return action_map.get(action_int, 'log_only')

    def _choose_action_int(self, observation):
        """Internal: choose action as integer using epsilon-greedy"""
        obs_dict = observation if isinstance(observation, dict) else {}
        encoded = self.encoder.encode(obs_dict)
        if random.random() < self.epsilon:
            return random.choice(DefenderActions.ALL)
        return self.qtable.best_action(encoded)

    def update_q_table(self, obs, action, reward, next_obs):
        """Update Q-table — called by simulation engine each step"""
        action_map = {
            'log_only': 0, 'rate_limit': 1,
            'block_ip': 2, 'isolate_target': 3
        }
        action_int = action_map.get(action, 0) if isinstance(action, str) else action
        self.update_q(obs, action_int, reward, next_obs)

    def decay_epsilon(self):
        """Decay exploration rate — called by simulation engine per episode"""
        if self.epsilon > self.epsilon_min:
            self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

    def save_model(self):
        """Save Q-table — called by simulation engine"""
        self.qtable.save(DEFENDER_MODEL_PATH)

# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE TEST / DEMO
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Running DefenderAI in REAL MODE — live Snort alerts")

    agent = DefenderAI()
    agent.load_model()
    agent.ids.start()

    episode = 0

    try:
        while True:
            episode += 1
            agent.start_episode()
            logger.info(f"Episode {episode} started — monitoring real traffic...")

            for step in range(50):
                # Get real observation from live network
                obs = agent.observe(suspicious_ip=ATTACKER_IP)

                alert_count = obs.get("alert_count", 0)
                logger.info(f"  Step {step+1}: alerts={alert_count} "
                           f"severity={obs.get('alert_severity',0)} "
                           f"pps={obs.get('traffic_rate_pps',0):.1f}")

                # Choose action based on real observations
                action = agent._choose_action_int(obs)
                action_name = DefenderActions.name(action)

                # Execute real firewall action
                result = agent.execute_action(action,
                                             target_ip=TARGET_IP,
                                             suspicious_ip=ATTACKER_IP)

                # Determine if attack was real
                attack_happening = alert_count > 0
                attack_succeeded = attack_happening and not result["success"]

                # Get reward
                reward = agent.receive_reward(action, attack_happening,
                                            attack_succeeded)

                # Get next observation
                next_obs = agent.observe(suspicious_ip=ATTACKER_IP)

                # Update Q-table
                agent.update_q(obs, action, reward, next_obs)

                logger.info(f"  Action: {action_name} | "
                           f"Reward: {reward:+.1f} | "
                           f"Result: {result['message']}")

                time.sleep(5)  # Check every 5 seconds

            agent.decay_epsilon()
            summary = agent.end_episode()
            logger.info(f"Episode {episode} done: "
                       f"reward={summary['total_reward']:.2f}")
            time.sleep(10)

    except KeyboardInterrupt:
        logger.info("Stopping DefenderAI...")
        agent.save_model()
        agent.ids.stop()
        logger.info("Model saved. Goodbye!")
