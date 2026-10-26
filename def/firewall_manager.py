"""
firewall_manager.py
===================
iptables-based firewall automation for the AI-vs-AI Cyber Defense Simulator.

Exposes four core defensive primitives:
    block_ip(ip)                  – DROP all traffic from an IP
    unblock_ip(ip)                – Remove block rule
    rate_limit_ip(ip, rate, burst)– Throttle traffic from an IP
    clear_rate_limits()           – Remove all rate-limit rules
    isolate_target(target, mgmt)  – Block all inbound to target except mgmt IP
    deisolate_target(target)      – Restore normal inbound to target

All rules are tracked in a local state file so they can be replayed
after reboot or cleaned up at the end of a simulation episode.

Requirements:
    - Python 3.8+
    - iptables installed  (sudo apt install iptables)
    - Script must run with sudo / root privileges on the DEFENDER VM

Chain strategy:
    We insert into the CYBERLAB_DEFENSE chain (custom chain), then
    jump to it from INPUT/FORWARD so we never touch the system base rules.
"""

import os
import json
import subprocess
import threading
import logging
from datetime import datetime
from typing import Optional

from config import (
    DEFENDER_IP, TARGET_IP, ATTACKER_IP,
    FIREWALL_STATE_FILE, LOG_DIR
)
from utils import get_logger, save_json, ensure_utf8_stdout

logger = get_logger("FirewallManager")

CHAIN_NAME = "CYBERLAB_DEFENSE"


# ═══════════════════════════════════════════════════════════════════════════
# LOW-LEVEL IPTABLES RUNNER
# ═══════════════════════════════════════════════════════════════════════════
class IPTablesRunner:
    """
    Thin wrapper around subprocess calls to iptables.
    Dry-run mode (DRY_RUN=True) prints commands without executing them.
    """
    DRY_RUN: bool = os.getenv("CYBERLAB_DRY_RUN", "0") == "1"

    def run(self, args: list, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["sudo", "iptables"] + args
        logger.debug(f"iptables: {' '.join(cmd)}")
        if self.DRY_RUN:
            logger.info(f"[DRY-RUN] {' '.join(cmd)}")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=10, check=check
            )
            if result.returncode != 0:
                logger.warning(f"iptables non-zero exit: {result.stderr.strip()}")
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables error: {e.stderr.strip()}")
            raise
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out.")
            raise

    def rule_exists(self, table_args: list) -> bool:
        """Check if a rule already exists (uses -C check flag)."""
        check_args = ["-C"] + table_args
        result = self.run(check_args, check=False)
        return result.returncode == 0


# ═══════════════════════════════════════════════════════════════════════════
# FIREWALL STATE TRACKER
# ═══════════════════════════════════════════════════════════════════════════
class FirewallState:
    """Tracks active rules in a JSON file for auditability and cleanup."""

    def __init__(self, path: str = None):
        self.path   = path or FIREWALL_STATE_FILE
        self._lock  = threading.Lock()
        self.state  = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    return json.load(f)
            except json.JSONDecodeError:
                pass
        return {"blocked_ips": [], "rate_limited_ips": {},
                "isolated_targets": [], "rules": []}

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self.state, f, indent=2)

    def add_blocked(self, ip: str):
        with self._lock:
            if ip not in self.state["blocked_ips"]:
                self.state["blocked_ips"].append(ip)
            self._save()

    def remove_blocked(self, ip: str):
        with self._lock:
            self.state["blocked_ips"] = [i for i in self.state["blocked_ips"] if i != ip]
            self._save()

    def is_blocked(self, ip: str) -> bool:
        return ip in self.state["blocked_ips"]

    def add_rate_limited(self, ip: str, rate: str, burst: int):
        with self._lock:
            self.state["rate_limited_ips"][ip] = {"rate": rate, "burst": burst,
                                                   "since": datetime.now().isoformat()}
            self._save()

    def remove_rate_limited(self, ip: str):
        with self._lock:
            self.state["rate_limited_ips"].pop(ip, None)
            self._save()

    def add_isolated(self, target_ip: str):
        with self._lock:
            if target_ip not in self.state["isolated_targets"]:
                self.state["isolated_targets"].append(target_ip)
            self._save()

    def remove_isolated(self, target_ip: str):
        with self._lock:
            self.state["isolated_targets"] = [
                i for i in self.state["isolated_targets"] if i != target_ip
            ]
            self._save()

    def is_isolated(self, target_ip: str) -> bool:
        return target_ip in self.state["isolated_targets"]

    def get_all_blocked(self) -> list:
        return list(self.state["blocked_ips"])

    def get_all_rate_limited(self) -> dict:
        return dict(self.state["rate_limited_ips"])

    def reset(self):
        """Forget every remembered rule (used after the iptables chain is flushed)."""
        with self._lock:
            self.state = {"blocked_ips": [], "rate_limited_ips": {},
                          "isolated_targets": [], "rules": []}
            self._save()


# ═══════════════════════════════════════════════════════════════════════════
# FIREWALL MANAGER (main class)
# ═══════════════════════════════════════════════════════════════════════════
class FirewallManager:
    """
    High-level defensive firewall operations.

    All methods return True on success, False on failure.
    Thread-safe via a reentrant lock.
    """

    def __init__(self,chain="AI_DEFENCE"):
        self.chain = chain
        self.ipt    = IPTablesRunner()
        self.fstate = FirewallState()
        self._lock  = threading.RLock()
        self._ensure_chain()
        logger.info("FirewallManager ready.")

    # ──────────────────────────────────────────────────────────────────────
    # CHAIN BOOTSTRAP
    # ──────────────────────────────────────────────────────────────────────
    def _ensure_chain(self):
        try:
            self.ipt.run(["-N", CHAIN_NAME], check=False)

            # Fix: remove duplicate -C from check
            if not self.ipt.rule_exists(["INPUT", "-j", CHAIN_NAME]):
                self.ipt.run(["-I", "INPUT", "-j", CHAIN_NAME])

            if not self.ipt.rule_exists(["FORWARD", "-j", CHAIN_NAME]):
                self.ipt.run(["-I", "FORWARD", "-j", CHAIN_NAME])

            logger.debug(f"Chain {CHAIN_NAME} is ready.")
        except Exception as e:
            logger.error(f"Could not create iptables chain: {e}")


    # ──────────────────────────────────────────────────────────────────────
    # BLOCK / UNBLOCK
    # ──────────────────────────────────────────────────────────────────────
    def block_ip(self, ip: str) -> bool:
        """
        Drop all inbound traffic from the given IP address.
        Inserts rule at the top of CYBERLAB_DEFENSE chain.
        """
        with self._lock:
            if self.fstate.is_blocked(ip):
                logger.info(f"{ip} is already blocked.")
                return True
            try:
                # Block in CYBERLAB_DEFENSE chain
                self.ipt.run(["-I", CHAIN_NAME, "1",
                              "-s", ip, "-j", "DROP"])
                # Also log before drop
                self.ipt.run(["-I", CHAIN_NAME, "1",
                              "-s", ip,
                              "-j", "LOG",
                              "--log-prefix", f"[CYBERLAB-BLOCK] ",
                              "--log-level", "4"], check=False)
                self.fstate.add_blocked(ip)
                self._audit_log("BLOCK", ip)
                logger.warning(f"[FIREWALL] BLOCKED {ip}")
                return True
            except Exception as e:
                logger.error(f"Failed to block {ip}: {e}")
                return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove block rule for an IP."""
        with self._lock:
            if not self.fstate.is_blocked(ip):
                logger.info(f"{ip} is not currently blocked.")
                return True
            try:
                self.ipt.run(["-D", CHAIN_NAME,
                              "-s", ip, "-j", "DROP"], check=False)
                self.ipt.run(["-D", CHAIN_NAME,
                              "-s", ip, "-j", "LOG",
                              "--log-prefix", f"[CYBERLAB-BLOCK] ",
                              "--log-level", "4"], check=False)
                self.fstate.remove_blocked(ip)
                self._audit_log("UNBLOCK", ip)
                logger.info(f"[FIREWALL] UNBLOCKED {ip}")
                return True
            except Exception as e:
                logger.error(f"Failed to unblock {ip}: {e}")
                return False

    # ──────────────────────────────────────────────────────────────────────
    # RATE LIMITING
    # ──────────────────────────────────────────────────────────────────────
    def rate_limit_ip(self, ip: str, rate: str = "30/min", burst: int = 50) -> bool:
        """
        Rate-limit traffic from an IP using iptables 'limit' match.
        rate format: "N/second" | "N/min" | "N/hour"
        burst: number of packets allowed as a burst.
        """
        with self._lock:
            try:
                # Remove any existing rate-limit for this IP first
                self._remove_rate_limit_rules(ip)

                # Insert rate-limit rule: allow up to `rate` (with burst),
                # then DROP excess.
                # Rule 1: Accept packets within the rate limit
                self.ipt.run([
                    "-I", CHAIN_NAME, "1",
                    "-s", ip,
                    "-m", "limit",
                    "--limit", rate,
                    "--limit-burst", str(burst),
                    "-j", "ACCEPT"
                ])
                # Rule 2: Drop packets that exceed the rate limit
                self.ipt.run([
                    "-I", CHAIN_NAME, "1",
                    "-s", ip,
                    "-m", "limit",
                    "--limit", rate,
                    "--limit-burst", str(burst),
                    "-j", "LOG",
                    "--log-prefix", "[CYBERLAB-RATELIMIT] ",
                    "--log-level", "4"
                ], check=False)
                self.ipt.run([
                    "-A", CHAIN_NAME,
                    "-s", ip,
                    "-j", "DROP"
                ])

                self.fstate.add_rate_limited(ip, rate, burst)
                self._audit_log("RATE_LIMIT", ip, extra={"rate": rate, "burst": burst})
                logger.info(f"[FIREWALL] RATE-LIMITED {ip} at {rate} burst={burst}")
                return True
            except Exception as e:
                logger.error(f"Failed to rate-limit {ip}: {e}")
                return False

    def _remove_rate_limit_rules(self, ip: str):
        """Remove all rate-limit rules for an IP (best-effort)."""
        # Flush rules for this IP from our chain
        # iptables doesn't support IP-specific flush; we delete known patterns
        self.ipt.run(["-D", CHAIN_NAME, "-s", ip, "-j", "DROP"], check=False)
        self.ipt.run(["-D", CHAIN_NAME, "-s", ip, "-m", "limit",
                      "-j", "ACCEPT"], check=False)
        self.ipt.run(["-D", CHAIN_NAME, "-s", ip, "-m", "limit",
                      "-j", "LOG",
                      "--log-prefix", "[CYBERLAB-RATELIMIT] ",
                      "--log-level", "4"], check=False)
        self.fstate.remove_rate_limited(ip)

    def clear_rate_limits(self):
        """Remove all rate-limit rules for all tracked IPs."""
        with self._lock:
            for ip in list(self.fstate.get_all_rate_limited().keys()):
                self._remove_rate_limit_rules(ip)
            logger.info("[FIREWALL] All rate-limits cleared.")

    # ──────────────────────────────────────────────────────────────────────
    # ISOLATION
    # ──────────────────────────────────────────────────────────────────────
    def isolate_target(self, target_ip: str,
                       allow_management_ip: str = None) -> bool:
        """
        Block ALL inbound traffic to target_ip except from the management IP.
        This simulates network isolation of a compromised machine.
        """
        with self._lock:
            if self.fstate.is_isolated(target_ip):
                logger.info(f"{target_ip} is already isolated.")
                return True
            try:
                mgmt_ip = allow_management_ip or DEFENDER_IP

                # Allow established/related first
                self.ipt.run([
                    "-I", CHAIN_NAME, "1",
                    "-d", target_ip,
                    "-m", "state", "--state", "ESTABLISHED,RELATED",
                    "-j", "ACCEPT"
                ])
                # Allow management IP
                self.ipt.run([
                    "-I", CHAIN_NAME, "1",
                    "-s", mgmt_ip, "-d", target_ip,
                    "-j", "ACCEPT"
                ])
                # Drop all other inbound to target
                self.ipt.run([
                    "-A", CHAIN_NAME,
                    "-d", target_ip,
                    "-j", "LOG",
                    "--log-prefix", "[CYBERLAB-ISOLATE] ",
                    "--log-level", "4"
                ], check=False)
                self.ipt.run([
                    "-A", CHAIN_NAME,
                    "-d", target_ip,
                    "-j", "DROP"
                ])

                self.fstate.add_isolated(target_ip)
                self._audit_log("ISOLATE", target_ip,
                                extra={"management_allowed": mgmt_ip})
                logger.warning(f"[FIREWALL] ISOLATED {target_ip} "
                               f"(management: {mgmt_ip})")
                return True
            except Exception as e:
                logger.error(f"Failed to isolate {target_ip}: {e}")
                return False

    def deisolate_target(self, target_ip: str) -> bool:
        """Remove isolation rules for a target IP."""
        with self._lock:
            if not self.fstate.is_isolated(target_ip):
                logger.info(f"{target_ip} is not isolated.")
                return True
            try:
                # Remove all rules targeting this destination
                self.ipt.run(["-D", CHAIN_NAME, "-d", target_ip,
                              "-j", "DROP"], check=False)
                self.ipt.run(["-D", CHAIN_NAME, "-d", target_ip,
                              "-j", "LOG",
                              "--log-prefix", "[CYBERLAB-ISOLATE] ",
                              "--log-level", "4"], check=False)
                # Note: accept rules for mgmt/established are left (harmless)
                self.fstate.remove_isolated(target_ip)
                self._audit_log("DEISOLATE", target_ip)
                logger.info(f"[FIREWALL] DEISOLATED {target_ip}")
                return True
            except Exception as e:
                logger.error(f"Failed to deisolate {target_ip}: {e}")
                return False

    # ──────────────────────────────────────────────────────────────────────
    # CLEANUP
    # ──────────────────────────────────────────────────────────────────────
    def flush_all_rules(self):
        """
        Flush the entire CYBERLAB_DEFENSE chain.
        Called at simulation reset / episode boundary.
        """
        with self._lock:
            try:
                self.ipt.run(["-F", CHAIN_NAME], check=False)
                # Reset state
                self.fstate.state["blocked_ips"]       = []
                self.fstate.state["rate_limited_ips"]  = {}
                self.fstate.state["isolated_targets"]  = []
                self.fstate._save()
                logger.info(f"[FIREWALL] Chain {CHAIN_NAME} flushed.")
            except Exception as e:
                logger.error(f"Failed to flush chain: {e}")

    def remove_chain(self):
        """Completely remove the CYBERLAB_DEFENSE chain (cleanup after simulation)."""
        with self._lock:
            self.flush_all_rules()
            self.ipt.run(["-D", "INPUT",   "-j", CHAIN_NAME], check=False)
            self.ipt.run(["-D", "FORWARD", "-j", CHAIN_NAME], check=False)
            self.ipt.run(["-X", CHAIN_NAME], check=False)
            logger.info(f"[FIREWALL] Chain {CHAIN_NAME} removed.")

    # ──────────────────────────────────────────────────────────────────────
    # STATUS / DIAGNOSTICS
    # ──────────────────────────────────────────────────────────────────────
    def list_rules(self) -> str:
        """Return current rules in CYBERLAB_DEFENSE chain as a string."""
        try:
            result = self.ipt.run(["-L", CHAIN_NAME, "-v", "-n", "--line-numbers"])
            return result.stdout
        except Exception as e:
            return f"Error listing rules: {e}"

    def get_status(self) -> dict:
        return {
            "chain"           : CHAIN_NAME,
            "blocked_ips"     : self.fstate.get_all_blocked(),
            "rate_limited_ips": self.fstate.get_all_rate_limited(),
            "isolated_targets": self.fstate.state["isolated_targets"],
            "dry_run"         : IPTablesRunner.DRY_RUN,
        }

    # ──────────────────────────────────────────────────────────────────────
    # AUDIT LOGGING
    # ──────────────────────────────────────────────────────────────────────
    def _audit_log(self, action: str, target: str, extra: dict = None):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action"   : action,
            "target"   : target,
            **(extra or {}),
        }
        log_path = os.path.join(LOG_DIR, "firewall_audit.jsonl")
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            with open(log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.warning(f"Could not write audit log: {e}")

    def _forget_rules(self):
        """The chain was just flushed, so forget what was installed in it.
        Otherwise block_ip / isolate_target / rate_limit_ip find their old entry
        ("already blocked") and skip installing the rule, and the saved state
        file keeps stale entries into the next run."""
        with self._lock:
            self.fstate.reset()

    def flush_episode_rules(self):
        """Flush temporary firewall rules for current episode."""
        print("[FirewallManager] Flushing episode firewall rules...")
        try:
            os.system(f"sudo iptables -F {self.chain}")
        except Exception as e:
            print(f"[FirewallManager] Could not flush episode rules: {e}")
        self._forget_rules()

    def flush_all_episode_rules(self):
        """Flush all firewall rules."""
        print("[FirewallManager] Flushing all firewall rules...")
        try:
            os.system(f"sudo iptables -F {self.chain}")
        except Exception as e:
            print(f"[FirewallManager] Could not flush all rules: {e}")
        self._forget_rules()
# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE TEST (runs in DRY_RUN mode automatically if not root)
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import sys
    ensure_utf8_stdout()
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    if os.geteuid() != 0:
        logger.warning("Not running as root → enabling DRY_RUN mode.")
        IPTablesRunner.DRY_RUN = True

    fw = FirewallManager()

    print("\n── Block Test ──")
    fw.block_ip(ATTACKER_IP)
    print(fw.get_status())

    print("\n── Rate-Limit Test ──")
    fw.rate_limit_ip("10.0.0.99", rate="20/min", burst=30)
    print(fw.get_status())

    print("\n── Isolate Target Test ──")
    fw.isolate_target(TARGET_IP, allow_management_ip=DEFENDER_IP)
    print(fw.get_status())

    print("\n── Rules in Chain ──")
    print(fw.list_rules())

    print("\n── Cleanup ──")
    fw.unblock_ip(ATTACKER_IP)
    fw.clear_rate_limits()
    fw.deisolate_target(TARGET_IP)
    print(fw.get_status())
