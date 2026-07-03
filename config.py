"""
Configuration settings for the AI-Assisted Network Traffic Analysis System
"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = DATA_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"

# Create directories if they don't exist
for dir_path in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, MODELS_DIR, LOGS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Network capture settings
CAPTURE_INTERFACE = "eth0"  # Default network interface
CAPTURE_DURATION = 60  # Default capture duration in seconds
CAPTURE_FILTER = ""  # BPF filter for packet capture
PACKET_COUNT = 10000  # Maximum packets to capture

# Zeek settings
ZEEK_PATH = "zeek"  # Path to zeek executable
ZEEK_SCRIPTS_DIR = BASE_DIR / "zeek_scripts"
ZEEK_LOG_DIR = DATA_DIR / "zeek_logs"

# ML Model settings
MODELS_TO_EVALUATE = [
    "random_forest",
    "svm",
    "xgboost",
    "decision_tree",
    "logistic_regression"
]

DEFAULT_MODEL = "random_forest"
TEST_SIZE = 0.2
RANDOM_STATE = 42

# Model hyperparameters
MODEL_PARAMS = {
    "random_forest": {
        "n_estimators": 100,
        "max_depth": 10,
        "random_state": RANDOM_STATE,
        "n_jobs": -1
    },
    "svm": {
        "kernel": "rbf",
        "C": 1.0,
        "gamma": "scale",
        "random_state": RANDOM_STATE
    },
    "xgboost": {
        "n_estimators": 100,
        "max_depth": 6,
        "learning_rate": 0.1,
        "random_state": RANDOM_STATE,
        "n_jobs": -1
    },
    "decision_tree": {
        "max_depth": 10,
        "random_state": RANDOM_STATE
    },
    "logistic_regression": {
        "max_iter": 1000,
        "random_state": RANDOM_STATE,
        "n_jobs": -1
    }
}

# IDS/IPS settings
IDS_ENABLED = True
IPS_ENABLED = True
IDS_THRESHOLD = 0.7  # Confidence threshold for attack detection
BLOCK_DURATION = 300  # Duration to block IP in seconds

# DDoS simulation settings
DDOS_TARGET_IP = "127.0.0.1"
DDOS_TARGET_PORT = 80
DDOS_PACKET_RATE = 1000  # Packets per second
DDOS_ATTACK_TYPES = ["syn_flood", "udp_flood", "icmp_flood"]

# Logging settings
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Feature extraction settings
FEATURE_COLUMNS = [
    "packet_size",
    "protocol",
    "src_port",
    "dst_port",
    "flags",
    "flow_duration",
    "packet_count",
    "byte_count",
    "packet_rate",
    "byte_rate"
]

# Attack labels
ATTACK_LABELS = {
    "normal": 0,
    "ddos": 1,
    "port_scan": 2,
    "dos": 3,
    "probe": 4
}
