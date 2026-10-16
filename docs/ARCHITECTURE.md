# ARAN Architecture

## Overview

ARAN is a modular monolith. All security processing runs in Java.
The frontend is a pure presentation layer with no business logic.

```
┌─────────────────────────────────────────────────────────┐
│                    SECURITY SOURCES                      │
│  REST API POST /api/event   │   logs/security-events.log│
│        (manual ingest)      │   (automatic monitoring)  │
└──────────────────┬──────────┴──────────────┬────────────┘
                   │                         │
                   ▼                         ▼
┌──────────────────────────────────────────────────────────┐
│                 EVENT INGESTION LAYER                    │
│                   EventService.java                      │
│   • Validates username, event type, IP address           │
│   • Normalises event type to uppercase                   │
│   • Creates SecurityEvent with UUID + timestamp          │
│   • Persists to EventRepository                          │
│   • Triggers detection pipeline                          │
└───────────────────────────────┬──────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────┐
│                    SECURITY ENGINE                       │
│             ThreatDetectionService.java                  │
│                                                          │
│   1. RiskScoreService calculates 0-100 score             │
│   2. Each ThreatDetector is evaluated in order:          │
│      ┌──────────────────────────────────────┐            │
│      │  MalwareDetector                     │            │
│      │  BruteForceDetector                  │            │
│      │  PrivilegeEscalationDetector         │            │
│      │  SensitiveFileDetector               │            │
│      │  BehaviourAnalyzer                   │            │
│      └──────────────────────────────────────┘            │
│   3. First matching detector produces threat type        │
│   4. Threat is created and saved                         │
│   5. Incident created if risk score ≥ threshold          │
└───────┬───────────────────────────┬──────────────────────┘
        │                           │
        ▼                           ▼
┌────────────────┐        ┌─────────────────────┐
│ ThreatRepository│       │ IncidentRepository  │
│ (in-memory)    │        │ (in-memory)         │
└────────────────┘        └─────────────────────┘
        │                           │
        └──────────────┬────────────┘
                       ▼
┌──────────────────────────────────────────────────────────┐
│                      STORAGE                             │
│  EventRepository → data/events.csv (file-backed)         │
│  ThreatRepository  → in-memory (CopyOnWriteArrayList)    │
│  IncidentRepository→ in-memory (CopyOnWriteArrayList)    │
│  AuditService      → logs/audit.log                      │
└───────────────────────────┬──────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────┐
│                     REST API                             │
│                   ApiServer.java                         │
│    Built on com.sun.net.httpserver.HttpServer (JDK)      │
│    18 endpoints — see README for full list               │
│    Serves dashboard/ as static files at /                │
│    CORS headers on all responses                         │
└───────┬──────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────┐
│                SOC DASHBOARD                             │
│    dashboard/index.html + css/styles.css                 │
│    dashboard/js/ (ES modules, no build step)             │
│    Polls backend every 5 seconds                         │
│    All values come from Java backend                     │
│    No hardcoded statistics                               │
└──────────────────────────────────────────────────────────┘
```

## Package Structure

| Package | Responsibility |
|---------|----------------|
| `aran` | Application entry point |
| `aran.api` | HTTP server, route handlers, JSON serialisation |
| `aran.detector` | One class per threat detection rule |
| `aran.model` | Immutable domain objects: SecurityEvent, Threat, Incident |
| `aran.monitor` | Log file watcher (LogMonitor) |
| `aran.security` | AuthenticationService (SHA-256 hashing) |
| `aran.service` | Business logic: EventService, ThreatDetectionService, RiskScoreService, ReportService, AuditService |
| `aran.storage` | Repository pattern: EventRepository, ThreatRepository, IncidentRepository |
| `aran.util` | AppConfig, Console, IpValidator |

## Thread Safety

| Component | Mechanism |
|-----------|-----------|
| EventRepository | `synchronized` write + `CopyOnWriteArrayList` |
| ThreatRepository | `CopyOnWriteArrayList` |
| IncidentRepository | `CopyOnWriteArrayList`, `synchronized` status update |
| LogMonitor | Single daemon thread; no shared mutable state except `volatile` flags |
| ApiServer | `CachedThreadPool` (one thread per request); repositories are thread-safe |
| AuditService | `synchronized` write method |

## Risk Score Formula

```
score = baseScore(eventType)
      + 30 if ≥ bruteforce.threshold LOGIN_FAILUREs in bruteforce.window.minutes
      + 15 if SENSITIVE_FILE_ACCESS
      + 10 if USB_INSERTED
      + 20 if PRIVILEGE_ESCALATION
      + 10 if MALWARE_DETECTED
      -  5 if IP is private (10.x, 192.168.x, 127.x)
      capped at 100

Risk levels:
  0–29   → LOW
  30–59  → MEDIUM
  60–79  → HIGH
  80–100 → CRITICAL
```

## Incident Lifecycle

```
OPEN → INVESTIGATING → CONTAINED → RESOLVED
```

Transitions are enforced by `Incident.parseStatus()`.
The frontend sends `PATCH /api/incidents/{id}` with `{"status":"..."}`.
The backend validates, updates in-memory state, returns updated JSON.

## Automatic Log Monitoring

```
logs/security-events.log
       │
       │  (polled every 1000ms by default)
       ▼
LogMonitor.monitorLoop()
       │
       │  RandomAccessFile.seek(lastPosition)
       │  reads new bytes only
       ▼
LogMonitor.processLine(line)
       │
       │  splits on '|': username|eventType|ip|details
       │  validates fields
       ▼
EventService.ingest(...)
       │
       ▼
ThreatDetectionService.analyze(...)
```

Key behaviours:
- Starts at **end** of file — does not replay history
- Handles file rotation (truncation resets position to 0)
- Skips blank lines silently
- Logs malformed lines as WARNING (does not crash)
- Monitor thread is daemon (does not prevent JVM shutdown)
