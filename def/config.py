"""
Shared Configuration for AI-vs-AI Cyber Defense Simulator
Contains network settings, IP addresses, ports, and global constants
COMPLETE VERSION - Compatible with all project scripts
"""

import os

# ═══════════════════════════════════════════════════════════════════════════
# NETWORK CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
NETWORK_SUBNET = "192.168.50.0/24"
INTERNAL_NETWORK_NAME = "cyberlab"

# VM IP Addresses
ATTACKER_IP = "192.168.50.10"
TARGET_IP = "192.168.50.20"
DEFENDER_IP = "192.168.50.30"
MONITOR_IP = "192.168.50.40"

# ═══════════════════════════════════════════════════════════════════════════
# SERVICE PORTS
# ═══════════════════════════════════════════════════════════════════════════
APACHE_PORT = 80
MYSQL_PORT = 3306
SSH_PORT = 22
SNORT_ALERT_PORT = 5000
DEFENDER_API_PORT = 8000
METRICS_PORT = 9090

# Target open ports list
OPEN_PORTS_TARGET = [80, 22, 3306]

# ═══════════════════════════════════════════════════════════════════════════
# ATTACK TYPES
# ═══════════════════════════════════════════════════════════════════════════
ATTACK_TYPES = {
    'IDLE': 0,
    'SCAN': 1,
    'SQL_INJECTION': 2,
    'BRUTE_FORCE': 3,
    'DDOS': 4
}

# ═══════════════════════════════════════════════════════════════════════════
# DEFENSE ACTIONS
# ═══════════════════════════════════════════════════════════════════════════
DEFENSE_ACTIONS = {
    'LOG_ONLY': 0,
    'RATE_LIMIT': 1,
    'BLOCK_IP': 2,
    'ISOLATE_TARGET': 3
}

# ═══════════════════════════════════════════════════════════════════════════
# REINFORCEMENT LEARNING PARAMETERS
# ═══════════════════════════════════════════════════════════════════════════
RL_CONFIG = {
    'learning_rate': 0.01,
    'discount_factor': 0.95,
    'epsilon_start': 1.0,
    'epsilon_end': 0.01,
    'epsilon_decay': 0.995,
    'episodes': 1000,
    'max_steps_per_episode': 100
}

# Individual constants (for backward compatibility)
TOTAL_EPISODES = 200
STEPS_PER_EPISODE = 100
LEARNING_RATE = 0.01
DISCOUNT_FACTOR = 0.95
EPSILON_START = 1.0
EPSILON_END = 0.01
EPSILON_DECAY = 0.995

# Defender-specific RL parameters
DEFENDER_LEARNING_RATE = 0.01
DEFENDER_DISCOUNT_FACTOR = 0.95
DEFENDER_EPSILON_START = 1.0
DEFENDER_EPSILON_END = 0.01
DEFENDER_EPSILON_DECAY = 0.995

# Attacker-specific RL parameters (same as defender for now)
ATTACKER_LEARNING_RATE = 0.01
ATTACKER_DISCOUNT_FACTOR = 0.95
ATTACKER_EPSILON_START = 1.0
ATTACKER_EPSILON_END = 0.01
ATTACKER_EPSILON_DECAY = 0.995

# ═══════════════════════════════════════════════════════════════════════════
# REWARD VALUES
# ═══════════════════════════════════════════════════════════════════════════
ATTACKER_REWARDS = {
    'successful_scan': 5,
    'successful_sql_injection': 20,
    'successful_brute_force': 15,
    'successful_ddos': 10,
    'detected': -30,
    'blocked': -50,
    'idle': -1
}

DEFENDER_REWARDS = {
    'successful_block': 25,
    'successful_detection': 15,
    'false_positive': -20,
    'missed_attack': -30,
    'unnecessary_isolation': -15,
    'idle': -1
}

# ═══════════════════════════════════════════════════════════════════════════
# SNORT IDS CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
SNORT_RULES_DIR = "/etc/snort/rules"
SNORT_LOG_DIR = "/var/log/snort"
SNORT_ALERT_FILE = "/mnt/target-snort/snort.alert.fast"
ALERT_SOCKET_PATH = "/tmp/snort_alerts.sock"

# IDS alert window (seconds)
IDS_ALERT_WINDOW_SECONDS = 30

# ═══════════════════════════════════════════════════════════════════════════
# FIREWALL CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
IPTABLES_CHAIN = "CYBERLAB_DEFENSE"
FIREWALL_STATE_FILE = "/var/log/cyber-sim/firewall_state.json"

# ═══════════════════════════════════════════════════════════════════════════
# DVWA CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
DVWA_URL = "http://192.168.50.20/DVWA"
DVWA_DIR = "/var/www/html/DVWA"
DVWA_LOGIN_URL = f"{DVWA_URL}/login.php"
# DVWA ships with these as its own public defaults; override via env vars
# if you changed them. Never put a real password here.
DVWA_DEFAULT_USER = os.environ.get("DVWA_USER", "admin")
DVWA_DEFAULT_PASS = os.environ.get("DVWA_PASS", "password")

# ═══════════════════════════════════════════════════════════════════════════
# LOGGING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════
LOG_DIR = "/var/log/cyber-sim"
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
SIMULATION_LOG_FILE = "/var/log/cyber-sim/simulation.log"

# ═══════════════════════════════════════════════════════════════════════════
# METRICS AND VISUALIZATION
# ═══════════════════════════════════════════════════════════════════════════
METRICS_FILE = "/var/log/cyber-sim/metrics.json"
METRICS_OUTPUT_DIR = "/var/log/cyber-sim/metrics"
GRAPHS_DIR = "/var/log/cyber-sim/graphs"

# ═══════════════════════════════════════════════════════════════════════════
# MODEL PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════
MODEL_SAVE_DIR = "/opt/cyberlab/models"
DEFENDER_MODEL_PATH = "/opt/cyberlab/models/defender_q_table.pkl"
ATTACKER_MODEL_PATH = "/opt/cyber-sim/attacker/models/q_table.pkl"


# ═══════════════════════════════════════════════════════════════════════════
# TIMEOUT AND RETRY SETTINGS
# ═══════════════════════════════════════════════════════════════════════════
CONNECTION_TIMEOUT = 5
MAX_RETRIES = 3
RETRY_DELAY = 2

# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION PARAMETERS
# ═══════════════════════════════════════════════════════════════════════════
STEP_DELAY_SECONDS = 0.1
ENV_RESET_BETWEEN_EPISODES = True
ATTACKER_DETECTION_THRESHOLD = 5

# ═══════════════════════════════════════════════════════════════════════════
# FEATURE ENGINEERING FOR RL
# ═══════════════════════════════════════════════════════════════════════════
STATE_FEATURES = {
    'attacker': [
        'open_ports_count',
        'previously_successful_attacks',
        'times_detected',
        'times_blocked',
        'current_firewall_rules',
        'target_response_time',
        'vulnerability_score'
    ],
    'defender': [
        'alerts_last_minute',
        'unique_source_ips',
        'traffic_rate_mbps',
        'suspicious_patterns_count',
        'current_blocks',
        'false_positive_rate',
        'system_load'
    ]
}

# ═══════════════════════════════════════════════════════════════════════════
# ACTION SPACE SIZES
# ═══════════════════════════════════════════════════════════════════════════
ATTACKER_ACTION_SPACE = len(ATTACK_TYPES)
DEFENDER_ACTION_SPACE = len(DEFENSE_ACTIONS)
ATTACKER_STATE_SPACE = len(STATE_FEATURES['attacker'])
DEFENDER_STATE_SPACE = len(STATE_FEATURES['defender'])
