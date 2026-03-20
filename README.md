<div align="center">

# CyberSim

**Cybersecurity Attack Scenario Simulator**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-D71F00?style=for-the-badge&logo=sqlalchemy&logoColor=white)](https://sqlalchemy.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/badge/CI-Passing-success?style=for-the-badge&logo=github-actions&logoColor=white)](.github/workflows/ci.yml)

*Model threats. Calculate risk. Simulate attacks.*

[Getting Started](#getting-started) | [Features](#features) | [API](#api-reference) | [Architecture](#architecture)

</div>

---

## Overview

CyberSim is a comprehensive cybersecurity simulation platform built with FastAPI.
It enables security professionals, red teamers, and educators to:

- **Calculate CVSS v3.1 scores** with full base metric support
- **Model attack scenarios** using the Cyber Kill Chain framework
- **Track vulnerabilities** with CVE-style entries and severity filtering
- **Manage asset inventories** with automated risk scoring
- **Profile threat actors** with attribution and sophistication tracking
- **Simulate multi-stage attacks** with probability analysis and mitigation recommendations

## Features

### Security Dashboard
Real-time overview of your threat landscape with KPI cards showing vulnerability
counts by severity, average CVSS scores, top risky assets, and recent CVE entries.

### CVSS v3.1 Calculator
Full implementation of the Common Vulnerability Scoring System v3.1 base score
calculation with all eight metrics:
- **Attack Vector (AV):** Network, Adjacent, Local, Physical
- **Attack Complexity (AC):** Low, High
- **Privileges Required (PR):** None, Low, High
- **User Interaction (UI):** None, Required
- **Scope (S):** Unchanged, Changed
- **Confidentiality (C):** None, Low, High
- **Integrity (I):** None, Low, High
- **Availability (A):** None, Low, High

### Attack Scenario Builder
Build attack scenarios mapped to the Lockheed Martin Cyber Kill Chain:
1. **Reconnaissance** -- Target identification and information gathering
2. **Weaponization** -- Malicious payload creation
3. **Delivery** -- Payload transmission to target
4. **Exploitation** -- Vulnerability exploitation
5. **Installation** -- Persistent access mechanism
6. **Command & Control** -- Remote communication channel
7. **Actions on Objectives** -- Mission execution

Each stage includes MITRE ATT&CK technique references.

### Vulnerability Database
Browse, search, and filter vulnerabilities with realistic CVE-style entries.
Pre-loaded with well-known CVEs including Log4Shell, PrintNightmare, Spring4Shell,
and the XZ Utils backdoor.

### Asset Inventory
Track organizational assets with:
- Asset type classification (Server, Database, Network Device, etc.)
- Environment tagging (Production, DMZ, Development)
- Criticality rating (Critical, High, Medium, Low)
- Automated risk scoring based on CVSS, exposure, and asset value

### Attack Simulation Engine
Run simulated attacks through selected kill chain stages with configurable:
- Attacker sophistication (Nation-State to Script Kiddie)
- Target asset criticality
- Stage-by-stage success probability
- Estimated timeline
- Automated mitigation recommendations

### Threat Actor Profiles
Track known threat actors with:
- Attribution and aliases
- Actor type (Nation-State, Cybercriminal)
- Origin country and sophistication level
- Motivation and activity timeline

## Getting Started

### Prerequisites
- Python 3.11+
- pip

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/cybersim.git
cd cybersim

# Run the start script
chmod +x start.sh
./start.sh
```

The application will be available at `http://localhost:8002`.

### Manual Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn app:app --host 0.0.0.0 --port 8002 --reload
```

### Docker

```bash
# Build and run
docker-compose up --build

# Or standalone
docker build -t cybersim .
docker run -p 8002:8002 cybersim
```

## Architecture

```
cybersim/
|-- app.py                    # FastAPI entry point, lifespan, routing
|-- config.py                 # Application configuration
|-- models/
|   |-- database.py           # SQLite + SQLAlchemy engine setup
|   |-- schemas.py            # ORM models + Pydantic schemas
|-- routes/
|   |-- api.py                # REST API endpoints (/api/*)
|   |-- views.py              # HTML template routes (/, /vulnerabilities, etc.)
|-- services/
|   |-- cvss.py               # CVSS v3.1 base score calculator
|   |-- simulator.py          # Attack simulation engine + kill chain
|-- templates/                # Jinja2 HTML templates
|-- static/
|   |-- css/style.css         # Dark hacker theme
|   |-- js/main.js            # Client-side interactivity
|-- tests/                    # pytest test suite
|-- seed_data/data.json       # Sample CVEs, actors, assets, scenarios
```

### Tech Stack

| Layer       | Technology                  |
|-------------|----------------------------|
| Backend     | FastAPI 0.109 + Python 3.11 |
| Database    | SQLite + SQLAlchemy 2.0     |
| Templates   | Jinja2                      |
| Validation  | Pydantic v2                 |
| Testing     | pytest + httpx              |
| API Docs    | Swagger UI (auto-generated) |
| Container   | Docker                      |

## API Reference

### Dashboard
| Method | Endpoint            | Description              |
|--------|---------------------|--------------------------|
| GET    | `/api/dashboard`    | Aggregate statistics     |

### Vulnerabilities
| Method | Endpoint                       | Description              |
|--------|--------------------------------|--------------------------|
| GET    | `/api/vulnerabilities`         | List (filter by severity, search) |
| GET    | `/api/vulnerabilities/{id}`    | Get by ID                |
| POST   | `/api/vulnerabilities`         | Create new               |
| PUT    | `/api/vulnerabilities/{id}`    | Update                   |
| DELETE | `/api/vulnerabilities/{id}`    | Delete                   |

### Attack Scenarios
| Method | Endpoint                  | Description              |
|--------|---------------------------|--------------------------|
| GET    | `/api/scenarios`          | List (filter by stage)   |
| GET    | `/api/scenarios/{id}`     | Get by ID                |
| POST   | `/api/scenarios`          | Create new               |
| PUT    | `/api/scenarios/{id}`     | Update                   |
| DELETE | `/api/scenarios/{id}`     | Delete                   |

### Assets
| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| GET    | `/api/assets`         | List (filter by type)    |
| GET    | `/api/assets/{id}`    | Get by ID                |
| POST   | `/api/assets`         | Create new               |
| PUT    | `/api/assets/{id}`    | Update                   |
| DELETE | `/api/assets/{id}`    | Delete                   |

### Threat Actors
| Method | Endpoint                  | Description              |
|--------|---------------------------|--------------------------|
| GET    | `/api/threat-actors`      | List all                 |
| POST   | `/api/threat-actors`      | Create new               |
| DELETE | `/api/threat-actors/{id}` | Delete                   |

### CVSS Calculator
| Method | Endpoint               | Description              |
|--------|------------------------|--------------------------|
| POST   | `/api/cvss/calculate`  | Calculate CVSS v3.1 score|

### Kill Chain & Simulation
| Method | Endpoint                              | Description                    |
|--------|---------------------------------------|--------------------------------|
| GET    | `/api/kill-chain`                     | All stages with techniques     |
| GET    | `/api/kill-chain/{stage}/techniques`  | Techniques for specific stage  |
| POST   | `/api/simulate`                       | Run attack simulation          |
| GET    | `/api/risk-score`                     | Calculate composite risk score |

### Interactive API Docs
- **Swagger UI:** `http://localhost:8002/docs`
- **ReDoc:** `http://localhost:8002/redoc`

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=. --cov-report=html
```

## Standards & Frameworks

- **CVSS v3.1** -- Common Vulnerability Scoring System
- **Cyber Kill Chain** -- Lockheed Martin intrusion analysis model
- **MITRE ATT&CK** -- Adversarial Tactics, Techniques & Common Knowledge
- **CVE** -- Common Vulnerabilities and Exposures naming standard

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built with FastAPI, SQLAlchemy, and a passion for cybersecurity.</sub>
</div>
