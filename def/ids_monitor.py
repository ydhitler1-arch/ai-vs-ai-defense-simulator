"""
ids_monitor.py
==============
Snort IDS alert parser and real-time network traffic monitor for the
AI-vs-AI Cyber Defense Simulator.

Responsibilities
----------------
1. Parse Snort's unified2 / fast-alert log formats.
2. Tail the Snort alert file in real time (non-blocking).
3. Maintain a sliding-window alert cache for the defender AI.
4. Compute per-IP traffic rates using scapy packet capture.
5. Expose a clean API used by DefenderAI.observe().

Snort alert path (fast format):
    /var/log/snort/alert

Snort unified2 binary log path:
    /var/log/snort/snort.log.*

Alert severity mapping (based on Snort priority):
    1 → HIGH (3)
    2 → MEDIUM (2)
    3 → LOW (1)
"""

import os
import re
import time
import threading
import logging
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import List, Dict, Optional

from config import (
    SNORT_ALERT_FILE, SNORT_LOG_DIR, TARGET_IP, ATTACKER_IP,
    IDS_ALERT_WINDOW_SECONDS, LOG_DIR
)
from utils import get_logger, save_json, ensure_utf8_stdout

try:
    from config import TRAFFIC_INTERFACE
except ImportError:  # config.py on this VM predates the setting
    TRAFFIC_INTERFACE = os.environ.get("CYBERLAB_INTERFACE", "enp0s8")

logger = get_logger("IDSMonitor")


# ═══════════════════════════════════════════════════════════════════════════
# ALERT DATA CLASS
# ═══════════════════════════════════════════════════════════════════════════
class SnortAlert:
    """Represents a single parsed Snort alert."""

    __slots__ = (
        "timestamp", "sid", "priority", "severity",
        "classification", "message", "src_ip", "src_port",
        "dst_ip", "dst_port", "protocol", "raw"
    )

    def __init__(self):
        self.timestamp      = datetime.now()
        self.sid            = 0
        self.priority       = 3
        self.severity       = 1
        self.classification = ""
        self.message        = ""
        self.src_ip         = ""
        self.src_port       = 0
        self.dst_ip         = ""
        self.dst_port       = 0
        self.protocol       = "TCP"
        self.raw            = ""

    def to_dict(self) -> dict:
        return {
            "timestamp"     : self.timestamp.isoformat(),
            "sid"           : self.sid,
            "priority"      : self.priority,
            "severity"      : self.severity,
            "classification": self.classification,
            "message"       : self.message,
            "src_ip"        : self.src_ip,
            "src_port"      : self.src_port,
            "dst_ip"        : self.dst_ip,
            "dst_port"      : self.dst_port,
            "protocol"      : self.protocol,
        }

    def __repr__(self):
        return (f"<SnortAlert [{self.message}] "
                f"{self.src_ip}:{self.src_port} → "
                f"{self.dst_ip}:{self.dst_port} "
                f"sev={self.severity} t={self.timestamp.strftime('%H:%M:%S')}>")


# ═══════════════════════════════════════════════════════════════════════════
# SNORT FAST-FORMAT PARSER
# ═══════════════════════════════════════════════════════════════════════════
class SnortFastParser:
    """
    Parses Snort's 'fast' alert output format.

    Example line:
    01/15-14:22:33.123456  [**] [1:1000001:1] SQL Injection Attempt [**]
    [Classification: Web Application Attack] [Priority: 1]
    {TCP} 192.168.50.10:54321 -> 192.168.50.20:80
    """

    # Regex patterns
    RE_HEADER = re.compile(
        r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+'
        r'\[(\d+):(\d+):\d+\]\s+(.+?)\s+\[\*\*\]'
    )
    RE_CLASS    = re.compile(r'\[Classification:\s*(.+?)\]')
    RE_PRIORITY = re.compile(r'\[Priority:\s*(\d+)\]')
    RE_PROTO    = re.compile(r'\{(\w+)\}\s+([\d.]+):?(\d*)\s+->\s+([\d.]+):?(\d*)')

    # Priority → severity mapping. The lab's custom Snort rules have no
    # classtype, so Snort prints "Priority: 0"; treat that as high severity
    # (every rule there is an attack signature) instead of the lowest.
    SEVERITY_MAP = {0: 3, 1: 3, 2: 2, 3: 1}   # snort priority → our severity

    def parse_block(self, block: str) -> Optional[SnortAlert]:
        """Parse a multi-line Snort fast-format alert block."""
        lines = [l.strip() for l in block.strip().splitlines() if l.strip()]
        if not lines:
            return None

        alert = SnortAlert()
        alert.raw = block

        # -- Header line --
        m = self.RE_HEADER.search(lines[0])
        if not m:
            # Try single-line format
            m = self.RE_HEADER.search(block)
            if not m:
                logger.debug(f"Could not parse alert header: {lines[0][:80]}")
                return None

        ts_str       = m.group(1)
        alert.sid    = int(m.group(3))
        alert.message= m.group(4).strip()

        # Parse timestamp (no year in snort fast format; assume current year)
        try:
            year = datetime.now().year
            alert.timestamp = datetime.strptime(f"{year}/{ts_str}", "%Y/%m/%d-%H:%M:%S.%f")
        except ValueError:
            alert.timestamp = datetime.now()

        # -- Classification --
        for line in lines:
            mc = self.RE_CLASS.search(line)
            if mc:
                alert.classification = mc.group(1).strip()
                break

        # -- Priority / Severity --
        for line in lines:
            mp = self.RE_PRIORITY.search(line)
            if mp:
                prio = int(mp.group(1))
                alert.priority = prio
                alert.severity = self.SEVERITY_MAP.get(prio, 1)
                break

        # -- Protocol / IPs / Ports --
        for line in lines:
            mpr = self.RE_PROTO.search(line)
            if mpr:
                alert.protocol = mpr.group(1)
                alert.src_ip   = mpr.group(2)
                alert.src_port = int(mpr.group(3)) if mpr.group(3) else 0
                alert.dst_ip   = mpr.group(4)
                alert.dst_port = int(mpr.group(5)) if mpr.group(5) else 0
                break

        return alert

    def parse_file_chunk(self, text: str) -> List[SnortAlert]:
        """Split text into alert blocks and parse each."""
        # Snort fast alerts are separated by blank lines (or newline between alert rows)
        # Each alert starts with a date pattern
        raw_blocks = re.split(r'\n(?=\d{2}/\d{2}-)', text)
        alerts = []
        for block in raw_blocks:
            if block.strip():
                alert = self.parse_block(block)
                if alert:
                    alerts.append(alert)
        return alerts


# ═══════════════════════════════════════════════════════════════════════════
# TRAFFIC RATE MONITOR
# ═══════════════════════════════════════════════════════════════════════════
class TrafficRateMonitor:
    """
    Monitors per-IP packet rates using tcpdump output (no root scapy needed
    in some environments). Falls back to parsing /proc/net/nf_conntrack.
    """

    def __init__(self, interface: str = "enp0s8", window_sec: int = 10):
        self.interface  = interface
        self.window_sec = window_sec
        self._rates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._lock      = threading.Lock()
        self._running   = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._capture_loop,
                                         daemon=True, name="TrafficMonitor")
        self._thread.start()
        logger.info(f"TrafficRateMonitor started on {self.interface}")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)

    def get_rate(self, ip: str) -> float:
        """Return packets-per-second for the given IP over the last window."""
        with self._lock:
            timestamps = list(self._rates.get(ip, deque()))
        if len(timestamps) < 2:
            return 0.0
        now    = time.time()
        recent = [t for t in timestamps if now - t <= self.window_sec]
        if len(recent) < 2:
            return 0.0
        elapsed = recent[-1] - recent[0]
        return len(recent) / max(elapsed, 0.001)

    def _capture_loop(self):
        """Use tcpdump to count packets per source IP."""
        cmd = ["tcpdump", "-i", self.interface, "-n", "-q",
               f"src net {ATTACKER_IP}/32 or dst net {TARGET_IP}/32",
               "--immediate-mode"]
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True
            )
            for line in proc.stdout:
                if not self._running:
                    break
                ip = self._extract_src_ip(line)
                if ip:
                    with self._lock:
                        self._rates[ip].append(time.time())
            proc.terminate()
        except FileNotFoundError:
            logger.warning("tcpdump not found; using fallback traffic estimation.")
            self._fallback_loop()
        except Exception as e:
            logger.error(f"TrafficRateMonitor error: {e}")

    def _fallback_loop(self):
        """Read /proc/net/dev for byte counts as a rough activity indicator."""
        prev_bytes: Dict[str, int] = {}
        while self._running:
            try:
                with open("/proc/net/dev") as f:
                    for line in f:
                        if self.interface in line:
                            parts  = line.split()
                            rx_now = int(parts[1])
                            prev   = prev_bytes.get(self.interface, rx_now)
                            delta  = max(rx_now - prev, 0)
                            if delta > 1000:  # > 1KB activity
                                # Attribute to known attacker IP as approximation
                                with self._lock:
                                    self._rates[ATTACKER_IP].append(time.time())
                            prev_bytes[self.interface] = rx_now
            except Exception:
                pass
            time.sleep(1)

    @staticmethod
    def _extract_src_ip(tcpdump_line: str) -> Optional[str]:
        """Extract source IP from a tcpdump line."""
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)\.\d+\s+>', tcpdump_line)
        if m:
            return m.group(1)
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+>', tcpdump_line)
        if m:
            return m.group(1)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# IDS MONITOR (main class used by DefenderAI)
# ═══════════════════════════════════════════════════════════════════════════
class IDSMonitor:
    """
    Central IDS monitor.  Combines:
        - Live Snort alert file tailing
        - In-memory alert cache with timestamps
        - Per-IP traffic rate tracking
        - Alert statistics for the defender AI

    Used by DefenderAI.observe() to build the current observation.
    """

    def __init__(self, alert_file: str = None, interface: str = None):
        self.alert_file   = alert_file or SNORT_ALERT_FILE
        self.parser       = SnortFastParser()
        self.traffic      = TrafficRateMonitor(interface=interface or TRAFFIC_INTERFACE)

        # Alert cache: list of SnortAlert objects
        self._cache: List[SnortAlert] = []
        self._cache_lock = threading.Lock()

        # File tail state
        self._file_position: int = 0
        self._tail_thread: Optional[threading.Thread] = None
        self._running = False

        # Per-IP alert counters (rolling)
        self._ip_alert_counts: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # Statistics
        self.stats = {
            "total_alerts"        : 0,
            "high_severity_alerts": 0,
            "sql_injection_alerts": 0,
            "scan_alerts"         : 0,
            "brute_force_alerts"  : 0,
            "false_positives"     : 0,
        }

        logger.info(f"IDSMonitor initialised. Alert file: {self.alert_file}")

    # ──────────────────────────────────────────────────────────────────────
    # START / STOP
    # ──────────────────────────────────────────────────────────────────────
    def start(self):
        """Start background alert tailing and traffic monitoring."""
        self._running     = True
        self._tail_thread = threading.Thread(
            target=self._tail_alert_file, daemon=True, name="AlertTailer"
        )
        self._tail_thread.start()
        self.traffic.start()
        logger.info("IDSMonitor started (alert tailer + traffic monitor).")

    def stop(self):
        """Gracefully stop background threads."""
        self._running = False
        self.traffic.stop()
        if self._tail_thread:
            self._tail_thread.join(timeout=5)
        logger.info("IDSMonitor stopped.")

    # ──────────────────────────────────────────────────────────────────────
    # ALERT FILE TAILER
    # ──────────────────────────────────────────────────────────────────────
    def _tail_alert_file(self):
        """Continuously tail the Snort alert file for new entries."""
        if not os.path.exists(self.alert_file):
            logger.warning(f"Alert file not found: {self.alert_file}. "
                           f"Waiting for Snort to create it…")
            # Wait up to 60 seconds for Snort to start
            for _ in range(60):
                if not self._running:
                    return
                if os.path.exists(self.alert_file):
                    break
                time.sleep(1)

        try:
            with open(self.alert_file, "r") as f:
                # Seek to end for live tailing (don't replay old alerts)
                f.seek(0, 2)
                self._file_position = f.tell()

                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    self._handle_new_line(line, f)
        except Exception as e:
            logger.error(f"Alert file tailing error: {e}", exc_info=True)

    def _handle_new_line(self, line: str, fh):
        """Buffer lines and flush complete alert blocks."""
        # Collect until we have a full alert block
        block_lines = [line]
        deadline    = time.time() + 0.5
        while time.time() < deadline:
            next_line = fh.readline()
            if not next_line:
                break
            block_lines.append(next_line)
            if re.match(r'\d{2}/\d{2}-', next_line):
                # Next alert started; push back isn't possible, process current block
                break

        block = "".join(block_lines)
        alert = self.parser.parse_block(block)
        if alert:
            self._ingest_alert(alert)

    def _ingest_alert(self, alert: SnortAlert):
        """Add alert to cache and update statistics."""
        with self._cache_lock:
            self._cache.append(alert)
            # Keep cache from growing unbounded (max 10 000 alerts)
            if len(self._cache) > 10_000:
                self._cache = self._cache[-5000:]

        # Update per-IP tracking
        if alert.src_ip:
            self._ip_alert_counts[alert.src_ip].append(alert.timestamp)

        # Update global stats
        self.stats["total_alerts"] += 1
        if alert.severity == 3:
            self.stats["high_severity_alerts"] += 1
        msg_lower = alert.message.lower()
        if "sql" in msg_lower or "injection" in msg_lower:
            self.stats["sql_injection_alerts"] += 1
        elif "scan" in msg_lower or "nmap" in msg_lower or "port" in msg_lower:
            self.stats["scan_alerts"] += 1
        elif "brute" in msg_lower or "login" in msg_lower or "auth" in msg_lower:
            self.stats["brute_force_alerts"] += 1

        logger.info(f"[ALERT] {alert}")

        # Persist alert to JSON log
        self._persist_alert(alert)

    def _persist_alert(self, alert: SnortAlert):
        """Append alert to a rolling JSON-lines log file."""
        try:
            log_path = os.path.join(LOG_DIR, "ids_alerts.jsonl")
            os.makedirs(LOG_DIR, exist_ok=True)
            with open(log_path, "a") as f:
                f.write(str(alert.to_dict()).replace("'", '"') + "\n")
        except Exception as e:
            logger.warning(f"Could not persist alert: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC API (used by DefenderAI.observe)
    # ──────────────────────────────────────────────────────────────────────
    def get_recent_alerts(self, seconds: int = None) -> List[dict]:
        """
        Return all alerts from the last `seconds` seconds.
        If seconds is None, uses IDS_ALERT_WINDOW_SECONDS from config.
        """
        seconds  = seconds or IDS_ALERT_WINDOW_SECONDS
        cutoff   = datetime.now() - timedelta(seconds=seconds)
        with self._cache_lock:
            recent = [a for a in self._cache if a.timestamp >= cutoff]
        return [a.to_dict() for a in recent]

    def get_alerts_by_ip(self, ip: str, seconds: int = None) -> List[dict]:
        """Return recent alerts from a specific source IP."""
        all_alerts = self.get_recent_alerts(seconds=seconds)
        return [a for a in all_alerts if a["src_ip"] == ip]

    def get_traffic_rate(self, ip: str) -> float:
        """Return packets-per-second for a given IP."""
        return self.traffic.get_rate(ip)

    def get_alert_count(self, seconds: int = 30) -> int:
        return len(self.get_recent_alerts(seconds=seconds))

    def get_max_severity(self, seconds: int = 30) -> int:
        alerts = self.get_recent_alerts(seconds=seconds)
        if not alerts:
            return 0
        return max(a["severity"] for a in alerts)

    def is_ip_active(self, ip: str, seconds: int = 60) -> bool:
        """Returns True if the IP has generated any alerts in the last `seconds`."""
        return len(self.get_alerts_by_ip(ip, seconds=seconds)) > 0

    def get_top_attackers(self, n: int = 5, seconds: int = 300) -> List[dict]:
        """Return top N source IPs by alert count in the last `seconds`."""
        alerts = self.get_recent_alerts(seconds=seconds)
        counts: Dict[str, int] = defaultdict(int)
        for a in alerts:
            if a["src_ip"]:
                counts[a["src_ip"]] += 1
        sorted_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "alert_count": cnt} for ip, cnt in sorted_ips[:n]]

    def get_stats(self) -> dict:
        """Return cumulative IDS statistics."""
        return dict(self.stats)

    def clear_alerts(self):
        """Forget cached alerts. Called at the start of each episode so alerts
        from the previous episode (still inside the 30 s window) are not seen
        as recent. Cumulative statistics are kept."""
        with self._cache_lock:
            self._cache.clear()
        self._ip_alert_counts.clear()

    # ──────────────────────────────────────────────────────────────────────
    # MANUAL ALERT INJECTION (for testing / simulation without real Snort)
    # ──────────────────────────────────────────────────────────────────────
    def inject_simulated_alert(self, src_ip: str, dst_ip: str,
                                message: str, severity: int = 2,
                                protocol: str = "TCP",
                                src_port: int = 0, dst_port: int = 80):
        """
        Inject a synthetic alert directly into the cache.
        Used by the simulation engine when running without a real Snort instance.
        """
        alert             = SnortAlert()
        alert.src_ip      = src_ip
        alert.dst_ip      = dst_ip
        alert.message     = message
        alert.severity    = severity
        alert.priority    = {3: 1, 2: 2, 1: 3}.get(severity, 2)
        alert.protocol    = protocol
        alert.src_port    = src_port
        alert.dst_port    = dst_port
        alert.timestamp   = datetime.now()
        alert.classification = self._classify_message(message)
        self._ingest_alert(alert)
        logger.debug(f"Simulated alert injected: {alert}")

    @staticmethod
    def _classify_message(message: str) -> str:
        msg = message.lower()
        if "sql" in msg:
            return "Web Application Attack"
        elif "scan" in msg or "nmap" in msg:
            return "Network Scan"
        elif "brute" in msg or "login" in msg:
            return "Attempted Brute Force"
        elif "dos" in msg or "flood" in msg:
            return "Denial of Service"
        else:
            return "Potentially Bad Traffic"

    def poll_new_alerts(self) -> list:
        """Poll for new alerts since last call — wrapper for simulation engine"""
        return self.get_recent_alerts(seconds=IDS_ALERT_WINDOW_SECONDS)
    # ──────────────────────────────────────────────────────────────────────
    # SNORT PROCESS MANAGEMENT (optional helper)
    # ──────────────────────────────────────────────────────────────────────
    def start_snort(self, interface: str = "eth1",
                    config: str = "/etc/snort/snort.conf") -> bool:
        """Start Snort as a subprocess if not already running."""
        try:
            # Check if already running
            check = subprocess.run(["pgrep", "-x", "snort"],
                                   capture_output=True, text=True)
            if check.returncode == 0:
                logger.info("Snort already running.")
                return True

            cmd = [
                "sudo", "snort",
                "-i", interface,
                "-c", config,
                "-A", "fast",
                "-l", SNORT_LOG_DIR,
                "-D"               # daemonize
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("Snort started successfully.")
                return True
            else:
                logger.error(f"Snort start failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Could not start Snort: {e}")
            return False

    def stop_snort(self):
        """Stop the Snort daemon."""
        try:
            subprocess.run(["sudo", "pkill", "-x", "snort"],
                           capture_output=True)
            logger.info("Snort stopped.")
        except Exception as e:
            logger.warning(f"Could not stop Snort: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import time
    ensure_utf8_stdout()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    monitor = IDSMonitor()
    monitor.start()

    logger.info("Injecting 5 simulated alerts…")
    test_cases = [
        (ATTACKER_IP, TARGET_IP, "SQL Injection Attempt - DVWA",    3, "TCP", 55000, 80),
        (ATTACKER_IP, TARGET_IP, "NMAP Port Scan Detected",         2, "TCP", 55001, 0 ),
        (ATTACKER_IP, TARGET_IP, "Brute Force Login Attempt",       2, "TCP", 55002, 22),
        (ATTACKER_IP, TARGET_IP, "SQL UNION SELECT Attack",         3, "TCP", 55003, 80),
        ("10.0.0.99",  TARGET_IP, "Suspicious Outbound Traffic",    1, "UDP", 40000, 53),
    ]

    for tc in test_cases:
        monitor.inject_simulated_alert(*tc)
        time.sleep(0.3)

    time.sleep(1)

    print("\n── Recent Alerts ──")
    for a in monitor.get_recent_alerts(seconds=60):
        print(f"  {a['timestamp'][:19]}  sev={a['severity']}  {a['message']}"
              f"  {a['src_ip']}:{a['src_port']} → {a['dst_ip']}:{a['dst_port']}")

    print(f"\n── Top Attackers ──")
    for t in monitor.get_top_attackers(n=3):
        print(f"  {t['ip']}  →  {t['alert_count']} alerts")

    print(f"\n── Stats ──")
    for k, v in monitor.get_stats().items():
        print(f"  {k}: {v}")

    monitor.stop()
    logger.info("IDSMonitor standalone test complete.")
