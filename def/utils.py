"""
Utility Functions for AI-vs-AI Cyber Defense Simulator
Complete version with all functions needed by all project scripts
"""

import logging
import socket
import json
import time
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import subprocess
import requests
from pathlib import Path

from config import (
    LOG_DIR, LOG_LEVEL, LOG_FORMAT, CONNECTION_TIMEOUT,
    MAX_RETRIES, RETRY_DELAY
)


# ═══════════════════════════════════════════════════════════════════════════
# CONSOLE OUTPUT
# ═══════════════════════════════════════════════════════════════════════════

def ensure_utf8_stdout():
    """
    Make stdout/stderr tolerate Unicode (box-drawing chars, arrows, ✓/✗, …)
    used throughout this project's console output and plain print() calls.

    On Linux (the lab VMs) stdout is UTF-8 by default, so this is a no-op
    there. On Windows, the console defaults to a legacy codepage (e.g.
    cp1252) that can't encode those characters, and a bare print() with one
    of them raises UnicodeEncodeError and crashes the script. Call this once
    near the top of a script's entry point, before any such print().
    """
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass  # best-effort; never let this helper itself crash the script


# ═══════════════════════════════════════════════════════════════════════════
# LOGGING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def setup_logger(component_name: str, log_file: str = None, level: str = None) -> logging.Logger:
    """
    Setup logger for a specific component (used by main.py and other scripts).
    This is an alias for setup_logging with additional parameters.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    
    logger = logging.getLogger(component_name)
    logger.setLevel(getattr(logging, level or LOG_LEVEL))
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
    else:
        file_handler = logging.FileHandler(os.path.join(LOG_DIR, f"{component_name}.log"))
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


def get_logger(component_name: str) -> logging.Logger:
    """
    Get or create a logger for a component (used by defender_ai.py and other scripts).
    """
    return setup_logger(component_name)


def setup_logging(component_name: str) -> logging.Logger:
    """Setup logging for a specific component (backward compatibility)."""
    return setup_logger(component_name)


# ═══════════════════════════════════════════════════════════════════════════
# TIMESTAMP AND TIME FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def timestamp_now() -> str:
    """Create ISO format timestamp."""
    return datetime.now().isoformat()


def create_timestamp() -> str:
    """Create ISO format timestamp (alias)."""
    return datetime.now().isoformat()


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK CONNECTIVITY
# ═══════════════════════════════════════════════════════════════════════════

def check_connectivity(target_ip: str, port: int, timeout: int = CONNECTION_TIMEOUT) -> bool:
    """Check if a target IP and port is accessible"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a specific port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def wait_for_service(host: str, port: int, timeout: int = 60) -> bool:
    """Wait for a service to become available"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if check_connectivity(host, port):
            return True
        time.sleep(1)
    return False


def is_valid_ip(ip: str) -> bool:
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def get_network_interfaces() -> Dict[str, str]:
    """Get network interface information"""
    interfaces = {}
    try:
        result = execute_command(['ip', 'addr', 'show'])
        if result['success']:
            lines = result['stdout'].split('\n')
            current_interface = None
            for line in lines:
                if line and not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        current_interface = parts[1].strip()
                elif 'inet ' in line and current_interface:
                    ip = line.strip().split()[1].split('/')[0]
                    interfaces[current_interface] = ip
    except:
        pass
    
    return interfaces


# ═══════════════════════════════════════════════════════════════════════════
# COMMAND EXECUTION
# ═══════════════════════════════════════════════════════════════════════════

def execute_command(command: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Execute a system command and return results"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'stdout': '',
            'stderr': 'Command timed out',
            'returncode': -1
        }
    except Exception as e:
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'returncode': -1
        }


def safe_execute_command(command: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Safe wrapper for execute_command (alias)."""
    return execute_command(command, timeout)


def retry_operation(func, max_retries: int = MAX_RETRIES, delay: int = RETRY_DELAY):
    """Retry an operation multiple times with delay"""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                raise e


# ═══════════════════════════════════════════════════════════════════════════
# FILE AND DIRECTORY OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════

def ensure_dir(directory: str):
    """Ensure directory exists, create if not"""
    os.makedirs(directory, exist_ok=True)


def ensure_directory(directory: str):
    """Ensure directory exists, create if not (alias)"""
    os.makedirs(directory, exist_ok=True)


def get_file_size(filepath: str) -> int:
    """Get file size in bytes"""
    try:
        return os.path.getsize(filepath)
    except:
        return 0


# ═══════════════════════════════════════════════════════════════════════════
# JSON OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════

def save_json(data: Dict[str, Any], filepath: str):
    """Save data to JSON file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def load_json(filepath: str) -> Dict[str, Any]:
    """Load data from JSON file."""
    if not os.path.exists(filepath):
        return {}
    with open(filepath, 'r') as f:
        return json.load(f)


# ═══════════════════════════════════════════════════════════════════════════
# METRICS OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════

def save_metrics(metrics: Dict[str, Any], filename: str):
    """Save metrics to a JSON file"""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    # Load existing metrics if file exists
    existing_metrics = []
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                existing_metrics = json.load(f)
        except:
            existing_metrics = []
    
    # Append new metrics
    metrics['timestamp'] = datetime.now().isoformat()
    existing_metrics.append(metrics)
    
    # Save back to file
    with open(filename, 'w') as f:
        json.dump(existing_metrics, f, indent=2)


def load_metrics(filename: str) -> List[Dict[str, Any]]:
    """Load metrics from a JSON file"""
    if not os.path.exists(filename):
        return []
    
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except:
        return []


# ═══════════════════════════════════════════════════════════════════════════
# SNORT / IDS OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════

def read_snort_alerts(alert_file: str, num_lines: int = 100) -> List[str]:
    """Read last N lines from Snort alert file."""
    if not os.path.exists(alert_file):
        return []
    
    try:
        with open(alert_file, 'r') as f:
            lines = f.readlines()
            return lines[-num_lines:]
    except Exception as e:
        logging.warning(f"Could not read Snort alerts: {e}")
        return []


def parse_alert_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a Snort alert line into structured data."""
    try:
        # Basic parsing - can be enhanced based on actual format
        return {
            'raw': line.strip(),
            'timestamp': datetime.now().isoformat()
        }
    except:
        return None


def flush_snort_alerts(alert_file: str):
    """Clear the Snort alert file."""
    try:
        if os.path.exists(alert_file):
            open(alert_file, 'w').close()
    except Exception as e:
        logging.warning(f"Could not flush Snort alerts: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# FIREWALL / IPTABLES OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════

def get_active_iptables_rules(chain: str = None) -> List[str]:
    """Get active iptables rules."""
    try:
        if chain:
            result = execute_command(['sudo', 'iptables', '-L', chain, '-n', '-v'])
        else:
            result = execute_command(['sudo', 'iptables', '-L', '-n', '-v'])
        
        if result['success']:
            return result['stdout'].split('\n')
        return []
    except Exception as e:
        logging.warning(f"Could not get iptables rules: {e}")
        return []


# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM STATISTICS
# ═══════════════════════════════════════════════════════════════════════════

def get_system_stats() -> Dict[str, float]:
    """Get current system statistics"""
    stats = {}
    
    try:
        # CPU usage
        with open('/proc/stat', 'r') as f:
            cpu_line = f.readline()
            cpu_values = [float(x) for x in cpu_line.split()[1:]]
            total = sum(cpu_values)
            idle = cpu_values[3]
            stats['cpu_usage'] = 100 * (1 - idle / total) if total > 0 else 0
    except:
        stats['cpu_usage'] = 0
    
    try:
        # Memory usage
        with open('/proc/meminfo', 'r') as f:
            mem_info = {}
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = int(parts[1].strip().split()[0])
                    mem_info[key] = value
        
        total_mem = mem_info.get('MemTotal', 0)
        free_mem = mem_info.get('MemFree', 0) + mem_info.get('Buffers', 0) + mem_info.get('Cached', 0)
        used_mem = total_mem - free_mem
        stats['memory_usage'] = 100 * (used_mem / total_mem) if total_mem > 0 else 0
    except:
        stats['memory_usage'] = 0
    
    return stats


# ═══════════════════════════════════════════════════════════════════════════
# DATA PROCESSING
# ═══════════════════════════════════════════════════════════════════════════

def normalize_state(state: List[float], min_vals: List[float], max_vals: List[float]) -> List[float]:
    """Normalize state values to [0, 1] range"""
    normalized = []
    for val, min_val, max_val in zip(state, min_vals, max_vals):
        if max_val - min_val > 0:
            normalized.append((val - min_val) / (max_val - min_val))
        else:
            normalized.append(0.0)
    return normalized


def normalize_reward(reward: float, min_reward: float, max_reward: float) -> float:
    """Normalize reward to [-1, 1] range."""
    if max_reward - min_reward > 0:
        return 2 * ((reward - min_reward) / (max_reward - min_reward)) - 1
    return 0.0


# ═══════════════════════════════════════════════════════════════════════════
# MISC UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def send_alert(target_url: str, alert_data: Dict[str, Any]) -> bool:
    """Send alert to a remote service"""
    try:
        response = requests.post(
            target_url,
            json=alert_data,
            timeout=CONNECTION_TIMEOUT
        )
        return response.status_code == 200
    except Exception:
        return False


def calculate_hash(data: str) -> str:
    """Calculate SHA256 hash of data"""
    import hashlib
    return hashlib.sha256(data.encode()).hexdigest()


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a log line into structured data"""
    try:
        # Expected format: timestamp - component - level - message
        parts = line.split(' - ', 3)
        if len(parts) == 4:
            return {
                'timestamp': parts[0],
                'component': parts[1],
                'level': parts[2],
                'message': parts[3].strip()
            }
    except:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════
# RATE LIMITER CLASS
# ═══════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Simple rate limiter implementation"""
    
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request from identifier is allowed"""
        current_time = time.time()
        
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Remove old requests outside time window
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if current_time - req_time < self.time_window
        ]
        
        # Check if under limit
        if len(self.requests[identifier]) < self.max_requests:
            self.requests[identifier].append(current_time)
            return True
        
        return False
    
    def reset(self, identifier: str):
        """Reset rate limit for identifier"""
        if identifier in self.requests:
            del self.requests[identifier]


# ═══════════════════════════════════════════════════════════════════════════
# DATA CLASSES FOR SIMULATION
# ═══════════════════════════════════════════════════════════════════════════

class Episode:
    """Represents a single simulation episode."""
    
    def __init__(self, episode_num: int):
        self.episode_num = episode_num
        self.steps = []
        self.summary = {}
        self.start_time = time.time()
    
    def add_step(self, step_result):
        """Add a step result to this episode."""
        self.steps.append(step_result)
    
    def set_summary(self, summary: Dict[str, Any]):
        """Set episode summary."""
        self.summary = summary
    
    def total_steps(self) -> int:
        """Return total number of steps in this episode."""
        return len(self.steps)
    
    def duration(self) -> float:
        """Return episode duration in seconds."""
        return time.time() - self.start_time


class StepResult:
    """Represents the result of a single simulation step."""
    
    def __init__(self, step: int, atk_action: str, atk_success: bool, atk_reward: float,
                 def_action: str, def_correct: bool, def_reward: float,
                 alert_count: int, response_time: float):
        self.step = step
        self.atk_action = atk_action
        self.atk_success = atk_success
        self.atk_reward = atk_reward
        self.def_action = def_action
        self.def_correct = def_correct
        self.def_reward = def_reward
        self.alert_count = alert_count
        self.response_time = response_time
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'step': self.step,
            'atk_action': self.atk_action,
            'atk_success': self.atk_success,
            'atk_reward': self.atk_reward,
            'def_action': self.def_action,
            'def_correct': self.def_correct,
            'def_reward': self.def_reward,
            'alert_count': self.alert_count,
            'response_time': self.response_time,
            'timestamp': self.timestamp
        }
