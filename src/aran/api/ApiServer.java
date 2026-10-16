package aran.api;

import aran.model.*;
import aran.service.*;
import aran.ml.MLLogAnalyzerService;
import aran.ml.MLLogClassifier;
import aran.storage.*;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.logging.Logger;
import java.util.stream.*;

/**
 * Embedded HTTP server providing the ARAN REST API and serving the dashboard.
 *
 * Endpoints:
 *   GET  /api/health
 *   GET  /api/events
 *   GET  /api/events/recent
 *   GET  /api/threats
 *   GET  /api/threats/recent
 *   GET  /api/incidents
 *   GET  /api/incidents/recent
 *   GET  /api/dashboard/summary
 *   GET  /api/risk/summary
 *   GET  /api/monitoring/status
 *   POST /api/monitor/start
 *   POST /api/monitor/stop
 *   POST /api/event
 *   POST /api/simulation/run
 *   POST /api/reports/generate
 *   GET  /api/incidents/{id}
 *   PATCH /api/incidents/{id}
 */
public class ApiServer implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(ApiServer.class.getName());

    private final HttpServer server;
    private final EventService eventService;
    private final EventRepository events;
    private final ThreatRepository threats;
    private final IncidentRepository incidents;
    private final ReportService reports;
    private final AuditService audit;
    private final MLLogAnalyzerService mlAnalyzer;
    private final AtomicBoolean monitoringEnabled = new AtomicBoolean(false);
    private final Runnable monitorStartAction;
    private final Runnable monitorStopAction;

    public ApiServer(int port, EventService eventService, EventRepository events,
                     ThreatRepository threats, IncidentRepository incidents,
                     AuditService audit) throws IOException {
        this(port, eventService, events, threats, incidents, audit, null, null);
    }

    public ApiServer(int port, EventService eventService, EventRepository events,
                     ThreatRepository threats, IncidentRepository incidents,
                     AuditService audit,
                     Runnable monitorStartAction, Runnable monitorStopAction) throws IOException {
        this.eventService = eventService;
        this.events = events;
        this.threats = threats;
        this.incidents = incidents;
        this.audit = audit;
        this.mlAnalyzer = new MLLogAnalyzerService(eventService, Path.of("config/ml-model.json"));
        this.reports = new ReportService(events, threats, incidents, audit);
        this.monitorStartAction = monitorStartAction;
        this.monitorStopAction = monitorStopAction;

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Register API routes
        server.createContext("/api/health",             ex -> handle(ex, this::handleHealth));
        server.createContext("/api/events/recent",      ex -> handle(ex, this::handleRecentEvents));
        server.createContext("/api/events",             ex -> handle(ex, this::handleEvents));
        server.createContext("/api/threats/recent",     ex -> handle(ex, this::handleRecentThreats));
        server.createContext("/api/threats",            ex -> handle(ex, this::handleThreats));
        server.createContext("/api/incidents/recent",   ex -> handle(ex, this::handleRecentIncidents));
        server.createContext("/api/incidents/",         ex -> handle(ex, this::handleIncidentDetail));
        server.createContext("/api/incidents",          ex -> handle(ex, this::handleIncidents));
        server.createContext("/api/dashboard/summary",  ex -> handle(ex, this::handleDashboardSummary));
        server.createContext("/api/risk/summary",       ex -> handle(ex, this::handleRiskSummary));
        server.createContext("/api/monitoring/status",  ex -> handle(ex, this::handleMonitoringStatus));
        server.createContext("/api/monitor/start",      ex -> handle(ex, this::handleMonitorStart));
        server.createContext("/api/monitor/stop",       ex -> handle(ex, this::handleMonitorStop));
        server.createContext("/api/event",              ex -> handle(ex, this::handleEventCreate));
        server.createContext("/api/simulation/run",     ex -> handle(ex, this::handleSimulation));
        server.createContext("/api/ml/status",           ex -> handle(ex, this::handleMLStatus));
        server.createContext("/api/ml/analyze",          ex -> handle(ex, this::handleMLAnalyze));
        server.createContext("/api/reports/generate",   ex -> handle(ex, this::handleReportGenerate));
        server.createContext("/",                       ex -> handle(ex, this::serveStatic));

        server.setExecutor(Executors.newCachedThreadPool());
    }

    public void start() {
        server.start();
        LOG.info("ARAN API server started on port " + server.getAddress().getPort());
    }

    public void setMonitoringState(boolean enabled) {
        monitoringEnabled.set(enabled);
    }

    // ─── Route Wrapper ────────────────────────────────────────────────────────

    @FunctionalInterface
    interface RouteHandler { void handle(HttpExchange ex) throws IOException; }

    private void handle(HttpExchange ex, RouteHandler route) throws IOException {
        try {
            addCors(ex);
            if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                ex.sendResponseHeaders(204, -1);
                return;
            }
            route.handle(ex);
        } catch (Exception e) {
            LOG.severe("Unhandled error in " + ex.getRequestURI() + ": " + e.getMessage());
            try { send(ex, 500, json("error", "Internal server error")); }
            catch (IOException ignored) {}
        } finally {
            ex.close();
        }
    }

    private void addCors(HttpExchange ex) {
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
    }

    // ─── Handlers ─────────────────────────────────────────────────────────────

    private void handleHealth(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        send(ex, 200, jsonObj(
            "status", "UP",
            "service", "ARAN",
            "version", "1.0",
            "storageMode", "FILE",
            "monitoring", monitoringEnabled.get(),
            "uptime", System.currentTimeMillis(),
            "events", events.count(),
            "threats", threats.count()
        ));
    }

    private void handleEvents(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        List<SecurityEvent> all = events.findAll();
        List<SecurityEvent> sorted = all.stream()
            .sorted(Comparator.comparing(SecurityEvent::getTimestamp).reversed())
            .collect(Collectors.toList());
        int limit = parseLimit(ex.getRequestURI().getQuery());
        if (limit > 0) sorted = sorted.stream().limit(limit).collect(Collectors.toList());
        send(ex, 200, jsonObj("count", all.size(), "events", eventsArray(sorted)));
    }

    private void handleRecentEvents(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        List<SecurityEvent> items = events.findRecent(10);
        send(ex, 200, jsonObj("events", eventsArray(items)));
    }

    private void handleThreats(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        List<Threat> all = threats.findAll();
        List<Threat> sorted = all.stream()
            .sorted(Comparator.comparing(Threat::getDetectedAt).reversed())
            .collect(Collectors.toList());
        int limit = parseLimit(ex.getRequestURI().getQuery());
        if (limit > 0) sorted = sorted.stream().limit(limit).collect(Collectors.toList());
        send(ex, 200, jsonObj("count", all.size(), "threats", threatsArray(sorted)));
    }

    private void handleRecentThreats(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        List<Threat> items = threats.findRecent(10);
        send(ex, 200, jsonObj("threats", threatsArray(items)));
    }

    private void handleIncidents(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        List<Incident> all = incidents.findAll();
        List<Incident> sorted = all.stream()
            .sorted(Comparator.comparing(Incident::getCreatedAt).reversed())
            .collect(Collectors.toList());
        int limit = parseLimit(ex.getRequestURI().getQuery());
        if (limit > 0) sorted = sorted.stream().limit(limit).collect(Collectors.toList());
        send(ex, 200, jsonObj("count", all.size(), "incidents", incidentsArray(sorted)));
    }

    private void handleRecentIncidents(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        List<Incident> items = incidents.findRecent(10);
        send(ex, 200, jsonObj("incidents", incidentsArray(items)));
    }

    private void handleDashboardSummary(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        List<Threat> threatList = threats.findAll();
        int avgRisk = threatList.isEmpty() ? 0 :
            (int) Math.round(threatList.stream().mapToInt(Threat::getRiskScore).average().orElse(0));
        send(ex, 200, jsonObj(
            "events",          events.count(),
            "threats",         threatList.size(),
            "incidents",       incidents.findAll().size(),
            "criticalThreats", threats.countBySeverity("CRITICAL"),
            "highThreats",     threats.countBySeverity("HIGH"),
            "mediumThreats",   threats.countBySeverity("MEDIUM"),
            "lowThreats",      threats.countBySeverity("LOW"),
            "averageRisk",     avgRisk,
            "monitoring",      monitoringEnabled.get(),
            "openIncidents",   (int) incidents.countOpen(),
            "status",          monitoringEnabled.get() ? "ACTIVE" : "INACTIVE"
        ));
    }

    private void handleRiskSummary(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        List<Threat> threatList = threats.findAll();
        int avg = threatList.isEmpty() ? 0 :
            (int) Math.round(threatList.stream().mapToInt(Threat::getRiskScore).average().orElse(0));
        send(ex, 200, jsonObj(
            "averageRisk",     avg,
            "riskLevel",       RiskLevel.fromScore(avg).name(),
            "criticalThreats", threats.countBySeverity("CRITICAL"),
            "highThreats",     threats.countBySeverity("HIGH"),
            "mediumThreats",   threats.countBySeverity("MEDIUM"),
            "lowThreats",      threats.countBySeverity("LOW"),
            "threats",         threatList.size()
        ));
    }

    private void handleMonitoringStatus(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        send(ex, 200, jsonObj(
            "monitoring", monitoringEnabled.get(),
            "status", monitoringEnabled.get() ? "ACTIVE" : "INACTIVE"
        ));
    }

    private void handleMonitorStart(HttpExchange ex) throws IOException {
        requireMethod(ex, "POST");
        if (monitorStartAction == null) {
            send(ex, 503, json("error", "Monitor control not available via API in this mode"));
            return;
        }
        try {
            monitorStartAction.run();
            monitoringEnabled.set(true);
            audit.log("API", "MONITOR_STARTED");
            send(ex, 200, jsonObj("status", "started", "monitoring", true));
        } catch (Exception e) {
            send(ex, 500, json("error", "Failed to start monitor: " + e.getMessage()));
        }
    }

    private void handleMonitorStop(HttpExchange ex) throws IOException {
        requireMethod(ex, "POST");
        if (monitorStopAction == null) {
            send(ex, 503, json("error", "Monitor control not available via API in this mode"));
            return;
        }
        monitorStopAction.run();
        monitoringEnabled.set(false);
        audit.log("API", "MONITOR_STOPPED");
        send(ex, 200, jsonObj("status", "stopped", "monitoring", false));
    }

    private void handleEventCreate(HttpExchange ex) throws IOException {
        requireMethod(ex, "POST");
        String body = readBody(ex);
        if (body.isEmpty()) { send(ex, 400, json("error", "Request body is required")); return; }

        String username, eventType, ipAddress, details;
        if (body.startsWith("{")) {
            username  = extractStr(body, "username");
            eventType = extractStr(body, "eventType");
            ipAddress = extractStr(body, "ipAddress");
            details   = extractStr(body, "details");
        } else {
            // Fallback: comma-separated (legacy)
            String[] p = body.split(",", 4);
            if (p.length < 3) { send(ex, 400, json("error", "Use JSON or: username,eventType,ip[,details]")); return; }
            username = p[0].trim(); eventType = p[1].trim(); ipAddress = p[2].trim();
            details  = p.length == 4 ? p[3].trim() : "";
        }

        if (username == null || username.isBlank()) { send(ex, 400, json("error", "username is required")); return; }
        if (eventType == null || eventType.isBlank()) { send(ex, 400, json("error", "eventType is required")); return; }

        try {
            SecurityEvent e = eventService.ingest(username, eventType, ipAddress == null ? "unknown" : ipAddress,
                "REST_API", details == null ? "" : details);
            send(ex, 201, jsonObj(
                "message",   "Event accepted",
                "eventId",   e.getId(),
                "username",  e.getUsername(),
                "eventType", e.getEventType(),
                "ipAddress", e.getIpAddress(),
                "severity",  e.getSeverity()
            ));
        } catch (IllegalArgumentException ex2) {
            send(ex, 400, json("error", ex2.getMessage()));
        }
    }

    private void handleMLStatus(HttpExchange ex) throws IOException {
        requireMethod(ex, "GET");
        send(ex, 200, jsonObj(
            "modelAvailable", mlAnalyzer.isModelAvailable(),
            "engine", mlAnalyzer.isModelAvailable()
                ? "ML: Multiclass Logistic Regression"
                : "Fallback: Deterministic Security Rules"
        ));
    }

    private void handleMLAnalyze(HttpExchange ex) throws IOException {
        requireMethod(ex, "POST");
        String body = readBody(ex);
        if (body.isEmpty()) { send(ex, 400, json("error", "Request body is required")); return; }

        String filename = extractJsonString(body, "filename");
        String content  = extractJsonString(body, "content");
        if (content == null) { send(ex, 400, json("error", "content is required")); return; }
        if (content.length() > 2_000_000) {
            send(ex, 413, json("error", "Log file is too large. Maximum supported size is 2 MB."));
            return;
        }

        MLLogAnalyzerService.BatchResult batch = mlAnalyzer.analyze(
            filename == null || filename.isBlank() ? "uploaded.log" : filename, content);

        StringBuilder arr = new StringBuilder("[");
        for (int i=0;i<batch.results().size();i++) {
            if (i>0) arr.append(',');
            MLLogAnalyzerService.LineResult r=batch.results().get(i);
            MLLogClassifier.Result c=r.classification();
            arr.append(jsonObj(
                "line", r.lineNumber(),
                "raw", r.raw(),
                "username", r.username(),
                "eventType", r.eventType(),
                "ipAddress", r.ipAddress(),
                "details", r.details(),
                "eventId", r.eventId(),
                "decision", c.decision().name(),
                "confidence", round3(c.confidence()),
                "safeProbability", round3(c.safeProbability()),
                "reviewProbability", round3(c.reviewProbability()),
                "blockProbability", round3(c.blockProbability()),
                "modelUsed", c.modelUsed(),
                "explanation", c.explanation(),
                "error", r.error()
            ));
        }
        arr.append(']');

        audit.log("ML_ANALYZER", "LOG_ANALYZED file=" + batch.filename()
            + " safe=" + batch.safe() + " review=" + batch.manualReview()
            + " blocked=" + batch.blocked() + " model=" + batch.modelAvailable());

        send(ex, 200, jsonObj(
            "filename", batch.filename(),
            "modelAvailable", batch.modelAvailable(),
            "engine", batch.modelAvailable()
                ? "ML: Multiclass Logistic Regression"
                : "Fallback: Deterministic Security Rules",
            "totalLines", batch.totalLines(),
            "validLines", batch.validLines(),
            "rejectedLines", batch.rejectedLines(),
            "safe", batch.safe(),
            "manualReview", batch.manualReview(),
            "blocked", batch.blocked(),
            "results", arr.toString()
        ));
    }

    private static double round3(double v) {
        return Math.round(v * 1000.0) / 1000.0;
    }

    private void handleSimulation(HttpExchange ex) throws IOException {
        requireMethod(ex, "POST");
        try {
            // Attack simulation: login failures + sensitive access + malware
            eventService.ingest("demo-user", "LOGIN_FAILURE", "203.0.113.50", "SIMULATION", "bad password");
            Thread.sleep(50);
            eventService.ingest("demo-user", "LOGIN_FAILURE", "203.0.113.50", "SIMULATION", "bad password");
            Thread.sleep(50);
            eventService.ingest("demo-user", "LOGIN_FAILURE", "203.0.113.50", "SIMULATION", "bad password");
            Thread.sleep(50);
            eventService.ingest("demo-user", "USB_INSERTED",         "203.0.113.50", "SIMULATION", "USB drive detected");
            Thread.sleep(50);
            eventService.ingest("demo-user", "SENSITIVE_FILE_ACCESS","203.0.113.50", "SIMULATION", "finance/payroll.csv");
            Thread.sleep(50);
            eventService.ingest("demo-user", "MALWARE_DETECTED",     "203.0.113.50", "SIMULATION", "malicious executable: dropper.exe");

            audit.log("API", "ATTACK_SIMULATION_RUN");
            send(ex, 200, jsonObj(
                "message",  "Attack simulation executed",
                "events",   6,
                "threats",  threats.findAll().size(),
                "incidents",incidents.findAll().size()
            ));
        } catch (Exception e) {
            LOG.severe("Simulation failed: " + e.getMessage());
            send(ex, 500, json("error", "Simulation failed: " + e.getMessage()));
        }
    }

    private void handleReportGenerate(HttpExchange ex) throws IOException {
        requireMethod(ex, "POST");
        try {
            Path reportPath = reports.generate();
            send(ex, 200, jsonObj(
                "message",  "Security report generated",
                "fileName", reportPath.getFileName().toString(),
                "path",     reportPath.toString()
            ));
        } catch (Exception e) {
            send(ex, 500, json("error", "Report generation failed: " + e.getMessage()));
        }
    }

    private void handleIncidentDetail(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        // Path: /api/incidents/{id}
        String[] parts = path.split("/");
        if (parts.length < 4 || parts[3].isBlank()) {
            // No ID given — delegate to list handler
            handleIncidents(ex);
            return;
        }
        String id = parts[3];

        if ("GET".equalsIgnoreCase(ex.getRequestMethod())) {
            Optional<Incident> inc = incidents.findById(id);
            if (inc.isEmpty()) { send(ex, 404, json("error", "Incident not found: " + id)); return; }
            send(ex, 200, incidentJson(inc.get()));
            return;
        }

        if ("PATCH".equalsIgnoreCase(ex.getRequestMethod())) {
            Optional<Incident> inc = incidents.findById(id);
            if (inc.isEmpty()) { send(ex, 404, json("error", "Incident not found: " + id)); return; }
            String body = readBody(ex);
            String statusStr = extractStr(body, "status");
            try {
                Incident.Status newStatus = Incident.parseStatus(statusStr);
                inc.get().setStatus(newStatus);
                incidents.update(inc.get());
                audit.log("API", "INCIDENT_UPDATED " + id + " status=" + newStatus);
                send(ex, 200, incidentJson(inc.get()));
            } catch (IllegalArgumentException e) {
                send(ex, 400, json("error", e.getMessage()));
            }
            return;
        }

        send(ex, 405, json("error", "Method not allowed. Use GET or PATCH."));
    }

    // ─── Static File Server ───────────────────────────────────────────────────

    private void serveStatic(HttpExchange ex) throws IOException {
        String reqPath = ex.getRequestURI().getPath();
        if (reqPath == null || reqPath.isBlank() || "/".equals(reqPath)) reqPath = "/index.html";

        // Serve from dashboard/ directory
        Path file = Path.of("dashboard" + reqPath);
        if (!Files.exists(file) || !Files.isRegularFile(file)) {
            // Try without the leading prefix
            if (reqPath.startsWith("/dashboard/")) file = Path.of("." + reqPath);
        }

        if (Files.exists(file) && Files.isRegularFile(file)) {
            byte[] data = Files.readAllBytes(file);
            ex.getResponseHeaders().set("Content-Type", contentType(file));
            ex.sendResponseHeaders(200, data.length);
            try (OutputStream out = ex.getResponseBody()) { out.write(data); }
            return;
        }

        // 404 page
        byte[] msg = ("ARAN — File not found: " + reqPath).getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(404, msg.length);
        try (OutputStream out = ex.getResponseBody()) { out.write(msg); }
    }

    private String contentType(Path f) {
        String n = f.getFileName().toString().toLowerCase(Locale.ROOT);
        if (n.endsWith(".html")) return "text/html; charset=utf-8";
        if (n.endsWith(".css"))  return "text/css; charset=utf-8";
        if (n.endsWith(".js"))   return "application/javascript; charset=utf-8";
        if (n.endsWith(".json")) return "application/json; charset=utf-8";
        if (n.endsWith(".svg"))  return "image/svg+xml";
        return "application/octet-stream";
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private void requireMethod(HttpExchange ex, String method) throws IOException {
        if (!method.equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, json("error", method + " required"));
            throw new IOException("Wrong method");
        }
    }

    private String readBody(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).trim();
    }

    private int parseLimit(String query) {
        if (query == null) return 0;
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2 && "limit".equalsIgnoreCase(kv[0])) {
                try { return Integer.parseInt(kv[1]); } catch (NumberFormatException ignored) {}
            }
        }
        return 0;
    }

    // ─── JSON Serialization ───────────────────────────────────────────────────

    private String eventJson(SecurityEvent e) {
        return jsonObj(
            "id",        e.getId(),
            "timestamp", e.getTimestamp().toString(),
            "username",  e.getUsername(),
            "eventType", e.getEventType(),
            "ipAddress", e.getIpAddress(),
            "source",    e.getSource(),
            "details",   e.getDetails(),
            "hostname",  e.getHostname(),
            "severity",  e.getSeverity()
        );
    }

    private String threatJson(Threat t) {
        return jsonObj(
            "id",          t.getId(),
            "eventId",     t.getEventId(),
            "type",        t.getType(),
            "severity",    t.getSeverity(),
            "riskScore",   t.getRiskScore(),
            "explanation", t.getExplanation(),
            "timestamp",   t.getDetectedAt().toString()
        );
    }

    private String incidentJson(Incident i) {
        return jsonObj(
            "id",        i.getId(),
            "title",     i.getTitle(),
            "threatId",  i.getThreatId(),
            "riskScore", i.getRiskScore(),
            "status",    i.getStatus().name(),
            "createdAt", i.getCreatedAt().toString(),
            "updatedAt", i.getUpdatedAt().toString()
        );
    }

    private String eventsArray(List<SecurityEvent> list) {
        return "[" + list.stream().map(this::eventJson).collect(Collectors.joining(",")) + "]";
    }

    private String threatsArray(List<Threat> list) {
        return "[" + list.stream().map(this::threatJson).collect(Collectors.joining(",")) + "]";
    }

    private String incidentsArray(List<Incident> list) {
        return "[" + list.stream().map(this::incidentJson).collect(Collectors.joining(",")) + "]";
    }

    private static String json(Object... kv) { return jsonObj(kv); }

    private static String jsonObj(Object... kv) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) sb.append(',');
            sb.append(jsonStr(String.valueOf(kv[i]))).append(':').append(toJson(kv[i + 1]));
        }
        return sb.append('}').toString();
    }

    private static String toJson(Object v) {
        if (v == null) return "null";
        if (v instanceof Number || v instanceof Boolean) return String.valueOf(v);
        String s = String.valueOf(v);
        // Only internally generated arrays are inserted as raw JSON.  Object-like
        // event values (for example a username beginning with "{") are still
        // ordinary strings and must be escaped to keep the response valid JSON.
        if (s.startsWith("[")) return s;
        return jsonStr(s);
    }

    private static String jsonStr(String s) {
        if (s == null) return "\"\"";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
                       .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }

    private static String extractJsonString(String json, String field) {
        String needle = "\"" + field + "\"";
        int key = json.indexOf(needle);
        if (key < 0) return null;
        int colon = json.indexOf(':', key + needle.length());
        if (colon < 0) return null;
        int i = colon + 1;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length() || json.charAt(i) != '"') return null;
        i++;
        StringBuilder out = new StringBuilder();
        boolean esc = false;
        while (i < json.length()) {
            char c = json.charAt(i++);
            if (esc) {
                switch (c) {
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case '\\' -> out.append('\\');
                    case '"' -> out.append('"');
                    case '/' -> out.append('/');
                    default -> out.append(c);
                }
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                return out.toString();
            } else {
                out.append(c);
            }
        }
        return null;
    }

    private static String extractStr(String json, String field) {
        if (json == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("\"" + field + "\"\\s*:\\s*\"([^\"]*)\"")
            .matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream out = ex.getResponseBody()) { out.write(b); }
    }

    @Override
    public void close() { server.stop(0); }
}
