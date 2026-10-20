# SentinelX Mini-SIEM

SentinelX is a beginner-level Security Information and Event Management (SIEM) project designed to simulate basic SOC monitoring and alert detection.

## Features

- Authentication log monitoring
- Brute-force detection
- Network port-scan detection
- Suspicious process detection
- Alert generation
- Alert severity classification
- Alert status management
- SOC statistics
- Investigation case management
- MITRE ATT&CK technique mapping
- FastAPI REST API
- Automated detection tests

## Detection Rules

| Detection | MITRE ATT&CK | Severity |
|---|---|---|
| Brute Force | T1110 | HIGH |
| Port Scan | T1046 | MEDIUM |
| Suspicious Process | T1059 | MEDIUM |

## Project Structure

```text
SentinelX/
│
├── backend/
│   ├── main.py
│   ├── log_reader.py
│   ├── alert_manager.py
│   ├── case_manager.py
│   └── report_generator.py
│
├── detections/
│   ├── brute_force.py
│   ├── port_scan.py
│   └── suspicious_process.py
│
├── logs/
│   ├── sample_auth.log
│   ├── network.log
│   └── process.log
│
├── tests/
│   ├── __init__.py
│   └── test_detections.py
│
├── .gitignore
├── README.md
└── requirements.txt
## Technology Stack

- Python
- FastAPI
- Pydantic
- Pytest
- JSON
- MITRE ATT&CK

## How It Works

SentinelX reads simulated security logs and passes them through detection rules.

```text
Security Logs
     ↓
Log Reader
     ↓
Detection Rules
     ↓
Alert Manager
     ↓
alerts.json
     ↓
FastAPI
     ↓
SOC Dashboard
## Example Detections

### Brute Force

Detects repeated failed login attempts from the same source within a defined time window.

### Port Scan

Detects a source IP contacting multiple different destination ports.

### Suspicious Process

Detects potentially suspicious processes such as:

- PowerShell
- CMD
- WScript
- CScript

## API Endpoints

```text
GET  /
GET  /alerts
GET  /alerts/{alert_id}
GET  /stats
GET  /cases
GET  /alerts/{alert_id}/case
POST /alerts/{alert_id}/case
PUT  /alerts/{alert_id}/status
## Disclaimer

SentinelX is an educational and portfolio project using simulated security logs. It is not intended to replace a production SIEM or security monitoring platform.