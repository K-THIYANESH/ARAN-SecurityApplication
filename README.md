# ARAN — Autonomous Risk Analysis & Network Security Platform

A working, integrated, college-level cybersecurity monitoring platform built entirely in Java.

## What ARAN Does

ARAN collects security events, runs threat detection, calculates risk scores, manages security incidents, and presents everything through a professional SOC dashboard.

```
Security Events → Validation → Threat Detection → Risk Scoring → Incidents → REST API → Dashboard
```

## Features

- **Real-time log monitoring** — automatically detects events appended to a log file
- **Threat detection engine** — BruteForceDetector, MalwareDetector, SensitiveFileDetector, PrivilegeEscalationDetector, BehaviourAnalyzer
- **Risk scoring (0–100)** — deterministic, fully explained
- **Incident management** — OPEN → INVESTIGATING → CONTAINED → RESOLVED lifecycle
- **REST API** — 18 endpoints served by a pure Java HTTP server
- **SOC Dashboard** — fully dynamic, all values from backend
- **Attack simulation** — generates real event sequences to demonstrate detection
- **ML Log Analyzer** — lightweight offline-trained 3-class logistic-regression model classifies uploaded logs as SAFE / MANUAL REVIEW / BLOCK
- **Safety fallback** — deterministic security rules take over automatically if the ML model is missing or inference fails
- **Sample input set** — `input/safe.log`, `input/manual-review.log`, and `input/suspicious-block.log` for instant demonstrations
- **Report generation** — saves timestamped text reports to `reports/`
- **File persistence** — events survive restarts (CSV), incidents/threats in-memory
- **Audit logging** — every important action logged to `logs/audit.log`

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Core engine | Java 21 |
| HTTP server | `com.sun.net.httpserver.HttpServer` (JDK built-in) |
| Storage | In-memory + CSV file (FILE mode), MySQL optional |
| Frontend | HTML5 + CSS3 + Vanilla JavaScript (ES Modules) |
| Charts | Chart.js (CDN) |
| Log monitoring | Java threads + `RandomAccessFile` |
| ML inference | Custom lightweight multinomial logistic regression (plain Java, JSON weights) |

## Requirements

- **Java 21** (JDK, not just JRE — you need `javac`)
- No Maven, no Docker, no Node.js, no external libraries

## Installation

### Windows

1. Install [Eclipse Temurin JDK 21](https://adoptium.net/)
2. Extract the project
3. Double-click `run.bat` **OR** open Command Prompt:
   ```cmd
   cd ARAN
   mkdir logs data reports out
   dir /s /b src\aran\*.java > sources.txt
   javac --release 21 -d out @sources.txt
   java -cp out aran.ARANApplication
   ```

### Linux / Mac

```bash
cd ARAN
mkdir -p logs data reports out
find src/aran -name "*.java" > /tmp/sources.txt
javac --release 21 -d out @/tmp/sources.txt
java -cp out aran.ARANApplication
```

Or simply: `chmod +x run.sh && ./run.sh`

## Running

### Interactive CLI mode (default)
```
java -cp out aran.ARANApplication
```
Login with `admin` / `admin123`. The REST API and dashboard auto-start.

### Headless server mode (API only)
```
java -cp out aran.ARANApplication --server
```
No login required. Use this for demos or when you only need the dashboard.

## Dashboard

After starting ARAN, open: **http://localhost:8080/**

The dashboard auto-refreshes every 5 seconds from the Java backend.

## Configuration (`config/application.properties`)

```properties
api.port=8080
storage.mode=FILE         # FILE or MYSQL
monitor.log.file=logs/security-events.log
monitor.interval.ms=1000
bruteforce.threshold=3
bruteforce.window.minutes=5
risk.threshold.high=60    # Incident created at this score
```

## Log Monitoring

ARAN watches `logs/security-events.log` for new lines. Format:

```
username|eventType|ipAddress|details
```

Examples:
```
admin|LOGIN_FAILURE|203.0.113.10|invalid password
jsmith|SENSITIVE_FILE_ACCESS|10.0.0.45|finance/payroll.csv
sysop|USB_INSERTED|192.168.1.100|USB drive inserted
attacker|MALWARE_DETECTED|198.51.100.1|dropper.exe
```

**Windows:**
```cmd
echo admin^|LOGIN_FAILURE^|10.0.0.1^|test >> logs\security-events.log
```

**Linux/Mac:**
```bash
echo "admin|LOGIN_FAILURE|10.0.0.1|test" >> logs/security-events.log
```

## Event Types

| Type | Severity | Description |
|------|----------|-------------|
| LOGIN_SUCCESS | LOW | Successful authentication |
| LOGIN_FAILURE | MEDIUM | Failed authentication |
| FILE_ACCESS | LOW | Normal file access |
| SENSITIVE_FILE_ACCESS | HIGH | Access to sensitive files |
| USB_INSERTED | MEDIUM | Removable media inserted |
| MALWARE_DETECTED | CRITICAL | Malware or suspicious executable |
| PRIVILEGE_ESCALATION | HIGH | User privilege escalation |
| NETWORK_SCAN | MEDIUM | Port scan detected |
| DATA_EXFILTRATION | HIGH | Data exfiltration attempt |
| ACCOUNT_LOCKOUT | MEDIUM | Account locked |

## ML Log Analyzer

Open **ML Log Analyzer** from the dashboard sidebar.

### Upload flow

```text
LOG FILE
   ↓
Parse username | eventType | IP | details
   ↓
Feature extraction + event context
   ↓
Lightweight ML model
   ↓  (if unavailable / inference error)
Deterministic fallback rules
   ↓
SAFE        MANUAL REVIEW        BLOCK
   ↓               ↓                 ↓
Normal       Analyst queue      Containment decision
```

The model is stored in `config/ml-model.json`. It is intentionally small and runs directly inside Java, so the project does **not** require Python, PyTorch, TensorFlow, ONNX Runtime, or internet access.

Sample files are available in:

```text
input/
├── safe.log
├── manual-review.log
└── suspicious-block.log
```

The accepted upload format is:

```text
username|eventType|ipAddress|details
```

The ML analyzer also sends accepted events through ARAN's existing threat-detection and audit pipeline, so the new feature complements rather than replaces the original simulation/rule engine.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Server status |
| GET | `/api/events` | All events (`?limit=N`) |
| GET | `/api/events/recent` | 10 most recent events |
| GET | `/api/threats` | All threats |
| GET | `/api/threats/recent` | 10 most recent threats |
| GET | `/api/incidents` | All incidents |
| GET | `/api/incidents/recent` | 10 most recent incidents |
| GET | `/api/incidents/{id}` | Single incident |
| PATCH | `/api/incidents/{id}` | Update status |
| GET | `/api/dashboard/summary` | KPI summary |
| GET | `/api/risk/summary` | Risk breakdown |
| GET | `/api/monitoring/status` | Monitor state |
| POST | `/api/monitor/start` | Start log monitor |
| POST | `/api/monitor/stop` | Stop log monitor |
| POST | `/api/event` | Ingest event |
| GET | `/api/ml/status` | ML model/fallback status |
| POST | `/api/ml/analyze` | Analyze and ingest an uploaded log | 
| POST | `/api/simulation/run` | Run attack simulation |
| POST | `/api/reports/generate` | Generate report |

## Attack Simulation Demo Flow

1. Start ARAN: `java -cp out aran.ARANApplication --server`
2. Open dashboard: http://localhost:8080/
3. Click **Run Simulation** — this ingests:
   - 3× LOGIN_FAILURE → BRUTE_FORCE threat
   - USB_INSERTED → tracked as removable media event
   - SENSITIVE_FILE_ACCESS → SUSPICIOUS_FILE_ACCESS threat + incident
   - MALWARE_DETECTED → MALWARE threat + CRITICAL incident
4. Watch dashboard KPIs update
5. Go to **Incidents** → change status OPEN → INVESTIGATING → RESOLVED
6. Click **Live Monitor** → append to `logs/security-events.log` → see it appear automatically
7. Go to **Reports** → Generate Report

## Threat Detection

| Detector | Triggers |
|----------|---------|
| BruteForceDetector | 3+ LOGIN_FAILURE for same user within 5 minutes |
| MalwareDetector | MALWARE_DETECTED event |
| SensitiveFileDetector | SENSITIVE_FILE_ACCESS event |
| PrivilegeEscalationDetector | PRIVILEGE_ESCALATION event |
| BehaviourAnalyzer | USB + SENSITIVE_FILE_ACCESS within 10 min; DATA_EXFILTRATION |

## Risk Scoring (0–100)

```
Score = baseScore(eventType)
      + 30 (if ≥3 login failures in window)
      + 15 (if sensitive file access)
      + 10 (if removable media)
      + 20 (if privilege escalation)
      + 10 (if malware)
      -  5 (if private IP: 10.x.x.x, 192.168.x.x)
      max 100
```

Incidents are created when risk score ≥ 60 (configurable).

## MySQL Setup (Optional)

1. Run `database/schema.sql` against your MySQL instance
2. In `config/application.properties`:
   ```properties
   storage.mode=MYSQL
   db.url=jdbc:mysql://localhost:3306/aran
   db.user=root
   db.password=yourpassword
   ```

## Project Structure

```
ARAN/
├── src/aran/
│   ├── ARANApplication.java      ← main entry point
│   ├── api/ApiServer.java        ← REST API (18 endpoints)
│   ├── detector/                 ← threat detectors
│   │   ├── ThreatDetector.java   ← interface
│   │   ├── BruteForceDetector.java
│   │   ├── MalwareDetector.java
│   │   ├── SensitiveFileDetector.java
│   │   ├── PrivilegeEscalationDetector.java
│   │   └── BehaviourAnalyzer.java
│   ├── model/                    ← SecurityEvent, Threat, Incident, etc.
│   ├── monitor/LogMonitor.java   ← automatic log watching
│   ├── security/AuthenticationService.java
│   ├── ml/                       ← Lightweight ML classifier + upload analyzer
│   ├── service/                  ← EventService, ThreatDetectionService, etc.
│   ├── storage/                  ← repositories
│   └── util/                     ← AppConfig, Console, IpValidator
├── dashboard/                    ← SOC dashboard (HTML + CSS + JS)
│   ├── index.html
│   ├── css/styles.css
│   └── js/
│       ├── app.js                ← router and app bootstrap
│       ├── api.js                ← API wrapper
│       ├── charts.js             ← Chart.js management
│       ├── notifications.js      ← Toast notifications
│       ├── utils.js              ← Shared utilities
│       └── pages/                ← One module per page
├── config/application.properties
├── config/ml-model.json          ← Offline-trained model weights
├── input/                        ← Safe / review / block demo logs
├── database/schema.sql
├── data/events.csv               ← Persistent event storage
├── logs/                         ← audit.log, security-events.log
└── reports/                      ← Generated reports
```

## Troubleshooting

**Port 8080 in use:**
```properties
# config/application.properties
api.port=9090
```

**Events not persisting:** Check `data/` directory is writable.

**Log monitor not picking up events:** Ensure the log file path in config matches and file exists.

**Dashboard shows "Backend Offline":** ARAN server is not running. Start it first.

## Default Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123 | Administrator |
| analyst | analyst123 | Analyst |

> Change these in `AuthenticationService.java` before deployment.
