# ARAN Test Cases

All test scenarios can be reproduced by running ARAN locally.

---

## TC-01: Successful Login (CLI)

**Action:** Start ARAN in interactive mode. Enter `admin` / `admin123`.  
**Expected:** `[OK] Authenticated as: admin`  
**API equivalent:** Start server; check `GET /api/health` returns `"status":"UP"`

---

## TC-02: Failed Login — 3 Attempts (CLI)

**Action:** Enter wrong password 3 times.  
**Expected:** ARAN exits with "Too many failed attempts."  
**Verify in:** `logs/audit.log` — 3× `CLI_LOGIN_FAILURE` entries

---

## TC-03: Ingest LOGIN_FAILURE Event

```bash
curl -X POST http://localhost:8080/api/event \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","eventType":"LOGIN_FAILURE","ipAddress":"203.0.113.5","details":"wrong password"}'
```

**Expected response:**
```json
{"message":"Event accepted","eventId":"...","eventType":"LOGIN_FAILURE","severity":"MEDIUM"}
```
**Verify:** `GET /api/events` shows the event. No threat created (single failure).

---

## TC-04: Brute Force Detection

**Action:** Ingest 3 `LOGIN_FAILURE` for same user within 5 minutes.

```bash
for i in 1 2 3; do
  curl -s -X POST http://localhost:8080/api/event \
    -H 'Content-Type: application/json' \
    -d '{"username":"bob","eventType":"LOGIN_FAILURE","ipAddress":"198.51.100.1","details":"attempt '$i'"}'
done
```

**Expected:**
- `GET /api/threats` shows `BRUTE_FORCE` threat
- Risk score ≥ 50 (base 20 + brute force bonus 30)
- Explanation contains "repeated login failures"

---

## TC-05: Malware Detection + Incident Creation

```bash
curl -X POST http://localhost:8080/api/event \
  -H 'Content-Type: application/json' \
  -d '{"username":"eve","eventType":"MALWARE_DETECTED","ipAddress":"198.51.100.99","details":"evil.exe"}'
```

**Expected:**
- Threat type: `MALWARE`, severity: `CRITICAL`
- Risk score: 85 (75 base + 10 malware bonus)
- `GET /api/incidents` shows a new `OPEN` incident
- Incident title: "Malware Detected on 198.51.100.99"

---

## TC-06: Private IP Discount

```bash
curl -X POST http://localhost:8080/api/event \
  -H 'Content-Type: application/json' \
  -d '{"username":"eve","eventType":"MALWARE_DETECTED","ipAddress":"10.0.0.1","details":"evil.exe"}'
```

**Expected:** Risk score = 80 (75 + 10 - 5 private IP discount)

---

## TC-07: Sensitive File Access

```bash
curl -X POST http://localhost:8080/api/event \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","eventType":"SENSITIVE_FILE_ACCESS","ipAddress":"192.168.1.5","details":"finance/payroll.csv"}'
```

**Expected:**
- Threat type: `SUSPICIOUS_FILE_ACCESS`, severity: `CRITICAL` (35 + 15 = 50 → MEDIUM)
- Actually: 35 + 15 - 5(private) = 45 → MEDIUM
- No incident (threshold 60 not reached)

---

## TC-08: USB + Sensitive File (Behaviour Analysis)

**Action:** Ingest USB_INSERTED followed by SENSITIVE_FILE_ACCESS for same user within 10 minutes.

```bash
curl -s -X POST http://localhost:8080/api/event -H 'Content-Type: application/json' \
  -d '{"username":"carol","eventType":"USB_INSERTED","ipAddress":"10.0.0.10","details":"USB"}'
sleep 1
curl -s -X POST http://localhost:8080/api/event -H 'Content-Type: application/json' \
  -d '{"username":"carol","eventType":"SENSITIVE_FILE_ACCESS","ipAddress":"10.0.0.10","details":"payroll.csv"}'
```

**Expected:** BehaviourAnalyzer detects `POTENTIAL_DATA_THEFT`

---

## TC-09: Privilege Escalation

```bash
curl -X POST http://localhost:8080/api/event \
  -H 'Content-Type: application/json' \
  -d '{"username":"charlie","eventType":"PRIVILEGE_ESCALATION","ipAddress":"203.0.113.20","details":"sudo su"}'
```

**Expected:**
- Threat type: `PRIVILEGE_ESCALATION`, severity: `CRITICAL` (60 + 20 = 80)
- Incident created: "Privilege Escalation by charlie"

---

## TC-10: Incident Status Update

```bash
# Get incident ID from TC-05 or TC-09
INC_ID="INC-XXXXXXXX"

curl -X PATCH http://localhost:8080/api/incidents/$INC_ID \
  -H 'Content-Type: application/json' \
  -d '{"status":"INVESTIGATING"}'

curl -X PATCH http://localhost:8080/api/incidents/$INC_ID \
  -H 'Content-Type: application/json' \
  -d '{"status":"CONTAINED"}'

curl -X PATCH http://localhost:8080/api/incidents/$INC_ID \
  -H 'Content-Type: application/json' \
  -d '{"status":"RESOLVED"}'
```

**Expected:** Each PATCH returns updated incident JSON with new status and updated `updatedAt` timestamp.

---

## TC-11: Attack Simulation

```bash
curl -X POST http://localhost:8080/api/simulation/run
```

**Expected:**
- 6 events ingested (3 LOGIN_FAILURE, USB_INSERTED, SENSITIVE_FILE_ACCESS, MALWARE_DETECTED)
- Multiple threats detected
- Multiple incidents created (HIGH/CRITICAL threshold)
- Dashboard KPIs update

---

## TC-12: Automatic Log Monitoring

**Action:**
```bash
echo "monitor-user|MALWARE_DETECTED|203.0.113.99|live test" >> logs/security-events.log
```

**Wait 1–2 seconds, then:**
```bash
curl -s http://localhost:8080/api/events/recent
```

**Expected:** The event appears with `"source":"AUTOMATIC_LOG"` — no UI action taken.

---

## TC-13: Report Generation

```bash
curl -X POST http://localhost:8080/api/reports/generate
```

**Expected:**
```json
{"message":"Security report generated","fileName":"ARAN-report-2026-...txt","path":"reports/..."}
```

File exists in `reports/` directory and contains executive summary, threat findings, and incident log.

---

## TC-14: Input Validation

```bash
# Empty username
curl -s -X POST http://localhost:8080/api/event \
  -H 'Content-Type: application/json' \
  -d '{"username":"","eventType":"LOGIN_FAILURE","ipAddress":"1.2.3.4"}'
# Expected: {"error":"username is required"}

# Missing event type
curl -s -X POST http://localhost:8080/api/event \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","eventType":"","ipAddress":"1.2.3.4"}'
# Expected: {"error":"eventType is required"}

# Invalid incident status
curl -s -X PATCH http://localhost:8080/api/incidents/INC-XXXXXXXX \
  -H 'Content-Type: application/json' \
  -d '{"status":"BOGUS"}'
# Expected: {"error":"Invalid status 'BOGUS'. Valid values: OPEN, INVESTIGATING, CONTAINED, RESOLVED"}

# Non-existent incident
curl -s http://localhost:8080/api/incidents/INC-NOTEXIST
# Expected: 404 {"error":"Incident not found: INC-NOTEXIST"}
```

---

## TC-15: Dashboard — Dynamic Data

1. Start ARAN with an empty `data/events.csv`
2. Open http://localhost:8080/
3. All KPI cards show 0
4. Run simulation
5. Dashboard auto-refreshes within 5 seconds
6. KPIs update to reflect actual backend data

**No hardcoded values should ever appear.**

---

## TC-16: Monitoring Status

```bash
# Check status
curl http://localhost:8080/api/monitoring/status
# Expected: {"monitoring":true,"status":"ACTIVE"}

# Stop monitor via API
curl -X POST http://localhost:8080/api/monitor/stop
# Expected: {"status":"stopped","monitoring":false}

# Start monitor via API
curl -X POST http://localhost:8080/api/monitor/start
# Expected: {"status":"started","monitoring":true}
```

---

## TC-17: Persistence

1. Ingest 3 events
2. Stop ARAN
3. Restart ARAN
4. `GET /api/events` — events still present (loaded from `data/events.csv`)

---

## Acceptance Checklist

| # | Test | Expected |
|---|------|----------|
| 1 | `GET /api/health` | `{"status":"UP"}` |
| 2 | CLI login admin/admin123 | Authenticated |
| 3 | POST /api/event LOGIN_FAILURE | 201 with eventId |
| 4 | 3× LOGIN_FAILURE → GET /api/threats | BRUTE_FORCE threat |
| 5 | MALWARE_DETECTED → GET /api/incidents | OPEN incident |
| 6 | PATCH incident status | Status updated |
| 7 | POST /api/simulation/run | 6 events, threats, incidents |
| 8 | Append to log file → GET /api/events/recent | Auto-ingested event |
| 9 | POST /api/reports/generate | File created in reports/ |
| 10 | Dashboard loads | No console errors, all data from API |
| 11 | Empty username POST | 400 error response |
| 12 | Invalid incident status PATCH | 400 error response |
| 13 | Restart ARAN | Events persisted |
