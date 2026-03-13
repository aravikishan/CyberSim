"""Application configuration for CyberSim."""

import os

# Server
HOST = "0.0.0.0"
PORT = int(os.environ.get("CYBERSIM_PORT", 8002))
DEBUG = os.environ.get("CYBERSIM_DEBUG", "false").lower() == "true"

# Database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "instance", "cybersim.db")
SQLALCHEMY_DATABASE_URI = os.environ.get(
    "DATABASE_URL", f"sqlite:///{DATABASE_PATH}"
)

# Application
APP_NAME = "CyberSim"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Cybersecurity Attack Scenario Simulator"

# CVSS v3.1 severity thresholds
SEVERITY_NONE = (0.0, 0.0)
SEVERITY_LOW = (0.1, 3.9)
SEVERITY_MEDIUM = (4.0, 6.9)
SEVERITY_HIGH = (7.0, 8.9)
SEVERITY_CRITICAL = (9.0, 10.0)

# Kill Chain stages
KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]

# Risk score weights
RISK_WEIGHT_VULN_SEVERITY = 0.4
RISK_WEIGHT_EXPOSURE = 0.3
RISK_WEIGHT_ASSET_VALUE = 0.3

# Seed data
SEED_DATA_PATH = os.path.join(BASE_DIR, "seed_data", "data.json")

# Testing
TESTING = False
