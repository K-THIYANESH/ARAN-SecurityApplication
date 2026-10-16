package aran;

import aran.api.ApiServer;
import aran.model.*;
import aran.monitor.LogMonitor;
import aran.security.AuthenticationService;
import aran.service.*;
import aran.storage.*;
import aran.util.AppConfig;
import aran.util.Console;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.*;
import java.util.logging.*;

/**
 * ARAN — Autonomous Risk Analysis & Network Security Platform
 *
 * Usage:
 *   java -cp out aran.ARANApplication          → interactive CLI + API
 *   java -cp out aran.ARANApplication --server → headless API-only mode (no CLI login required)
 */
public class ARANApplication {

    private final EventRepository eventRepo       = new EventRepository();
    private final ThreatRepository threatRepo     = new ThreatRepository();
    private final IncidentRepository incidentRepo = new IncidentRepository();
    private final AuditService audit              = new AuditService();
    private final ThreatDetectionService detector =
        new ThreatDetectionService(eventRepo, threatRepo, incidentRepo, audit);
    private final EventService eventService       =
        new EventService(eventRepo, detector, audit);
    private final ReportService reports           =
        new ReportService(eventRepo, threatRepo, incidentRepo, audit);
    private final AuthenticationService auth      = new AuthenticationService();

    private LogMonitor monitor;
    private ApiServer  api;

    public static void main(String[] args) {
        configureLogging();
        boolean serverMode = Arrays.asList(args).contains("--server");
        try {
            new ARANApplication().run(serverMode);
        } catch (Exception e) {
            Console.error("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void run(boolean serverMode) throws Exception {
        Console.header("ARAN — Autonomous Risk Analysis & Network Security Platform");
        System.out.println("  Version 1.0  |  Storage: " + AppConfig.storageMode() + "  |  Port: " + AppConfig.apiPort());

        // Auto-start monitor and API first (always)
        autoStart();

        if (serverMode) {
            System.out.println("\n[SERVER MODE] API running on http://localhost:" + AppConfig.apiPort());
            System.out.println("[SERVER MODE] Press Ctrl+C to stop.");
            // Block forever — shutdown hook handles cleanup
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                Console.info("Shutdown signal received. Stopping ARAN...");
                shutdown();
            }));
            Thread.currentThread().join(); // Block main thread
            return;
        }

        // Interactive CLI mode
        Scanner sc = new Scanner(System.in);
        if (!cliLogin(sc)) {
            Console.error("Too many failed login attempts. Exiting.");
            shutdown();
            return;
        }

        while (true) {
            printMenu();
            System.out.print("ARAN> ");
            String choice;
            try {
                choice = sc.nextLine().trim();
            } catch (NoSuchElementException e) {
                // EOF (e.g. running in a script) — exit cleanly
                Console.info("Input stream closed. Shutting down.");
                break;
            }
            try {
                switch (choice) {
                    case "1" -> manualEvent(sc);
                    case "2" -> viewEvents();
                    case "3" -> viewThreats();
                    case "4" -> viewIncidents();
                    case "5" -> toggleMonitor();
                    case "6" -> System.out.println("Report: " + reports.generate().toAbsolutePath());
                    case "7" -> System.out.println("API already running at http://localhost:" + AppConfig.apiPort());
                    case "8" -> runSimulation();
                    case "9" -> { shutdown(); return; }
                    default  -> System.out.println("Invalid option. Enter 1-9.");
                }
            } catch (NoSuchElementException e) {
                Console.info("Input stream ended. Shutting down.");
                break;
            } catch (Exception e) {
                Console.error("Operation failed: " + e.getMessage());
            }
        }
        shutdown();
    }

    private void printMenu() {
        System.out.println("\n────────────────────────────────────────");
        System.out.println("  1. Ingest Security Event");
        System.out.println("  2. View Events");
        System.out.println("  3. View Threats");
        System.out.println("  4. View Incidents");
        System.out.println("  5. " + (monitor != null ? "Stop" : "Start") + " Automatic Monitor");
        System.out.println("  6. Generate Report");
        System.out.println("  7. API Info");
        System.out.println("  8. Run Attack Simulation");
        System.out.println("  9. Exit");
        System.out.println("────────────────────────────────────────");
    }

    private boolean cliLogin(Scanner sc) {
        for (int attempt = 1; attempt <= 3; attempt++) {
            System.out.print("Username: ");
            String u;
            try { u = sc.nextLine().trim(); } catch (NoSuchElementException e) { return false; }
            System.out.print("Password: ");
            String p;
            try { p = sc.nextLine().trim(); } catch (NoSuchElementException e) { return false; }
            if (auth.authenticate(u, p)) {
                Console.status("OK", "Authenticated as: " + u);
                audit.log(u, "CLI_LOGIN_SUCCESS");
                return true;
            }
            audit.log(u, "CLI_LOGIN_FAILURE attempt=" + attempt);
            Console.status("HIGH", "Invalid credentials (attempt " + attempt + "/3)");
        }
        return false;
    }

    private void autoStart() throws Exception {
        // Start log monitor
        Path logFile = Path.of(AppConfig.monitorLogFile());
        monitor = new LogMonitor(logFile, eventService, AppConfig.monitorIntervalMs());
        monitor.start();
        audit.log("SYSTEM", "MONITOR_STARTED " + logFile);
        Console.status("OK", "Log monitor started on: " + logFile.toAbsolutePath());

        // Start REST API
        Runnable startMonitorFn = () -> {
            try {
                if (monitor == null || !monitor.isActive()) {
                    monitor = new LogMonitor(Path.of(AppConfig.monitorLogFile()), eventService);
                    monitor.start();
                    audit.log("API", "MONITOR_STARTED");
                }
            } catch (Exception e) { throw new RuntimeException("Failed to start monitor: " + e.getMessage(), e); }
        };
        Runnable stopMonitorFn = () -> {
            if (monitor != null) {
                monitor.stop();
                monitor = null;
                audit.log("API", "MONITOR_STOPPED");
            }
        };

        api = new ApiServer(AppConfig.apiPort(), eventService, eventRepo, threatRepo, incidentRepo,
                            audit, startMonitorFn, stopMonitorFn);
        api.setMonitoringState(true);
        api.start();
        audit.log("SYSTEM", "API_STARTED port=" + AppConfig.apiPort());
        Console.status("OK", "REST API running → http://localhost:" + AppConfig.apiPort());
        Console.status("OK", "Dashboard →       http://localhost:" + AppConfig.apiPort() + "/");
    }

    private void manualEvent(Scanner sc) {
        System.out.print("Username: "); String u = nextLine(sc);
        System.out.println("Types: LOGIN_SUCCESS, LOGIN_FAILURE, FILE_ACCESS, SENSITIVE_FILE_ACCESS,");
        System.out.println("       USB_INSERTED, MALWARE_DETECTED, PRIVILEGE_ESCALATION, NETWORK_SCAN");
        System.out.print("Event type: "); String t = nextLine(sc);
        System.out.print("IP Address: "); String ip = nextLine(sc);
        System.out.print("Details:    "); String d = nextLine(sc);
        SecurityEvent e = eventService.ingest(u, t, ip, "CLI", d);
        Console.status("OK", "Event accepted: " + e.getId());
    }

    private static String nextLine(Scanner sc) {
        try { return sc.nextLine().trim(); } catch (NoSuchElementException e) { return ""; }
    }

    private void viewEvents() {
        Console.header("Security Events (" + eventRepo.count() + " total)");
        eventRepo.findAll().stream()
            .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
            .limit(20)
            .forEach(e -> System.out.printf("  %s | %-20s | %-22s | %-15s | %s%n",
                e.getTimestamp().toString().substring(0, 19),
                e.getUsername(), e.getEventType(), e.getIpAddress(), e.getSource()));
    }

    private void viewThreats() {
        Console.header("Threat Findings (" + threatRepo.count() + " total)");
        threatRepo.findAll().stream()
            .sorted((a, b) -> b.getDetectedAt().compareTo(a.getDetectedAt()))
            .limit(20)
            .forEach(t -> Console.status(t.getSeverity(),
                t.getType() + " | risk=" + t.getRiskScore() + " | " + t.getExplanation()));
    }

    private void viewIncidents() {
        Console.header("Incidents (" + incidentRepo.findAll().size() + " total)");
        incidentRepo.findAll().stream()
            .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()))
            .limit(20)
            .forEach(i -> System.out.printf("  %-14s | %-12s | risk=%3d | %s%n",
                i.getId(), i.getStatus(), i.getRiskScore(), i.getTitle()));
    }

    private void toggleMonitor() throws Exception {
        if (monitor != null && monitor.isActive()) {
            monitor.stop(); monitor = null;
            if (api != null) api.setMonitoringState(false);
            audit.log("CLI", "MONITOR_STOPPED");
            Console.status("OK", "Automatic monitoring stopped.");
        } else {
            Path logFile = Path.of(AppConfig.monitorLogFile());
            monitor = new LogMonitor(logFile, eventService, AppConfig.monitorIntervalMs());
            monitor.start();
            if (api != null) api.setMonitoringState(true);
            audit.log("CLI", "MONITOR_STARTED");
            Console.status("OK", "Automatic monitoring started on: " + logFile.toAbsolutePath());
        }
    }

    private void runSimulation() throws Exception {
        Console.header("Attack Simulation");
        if (monitor == null || !monitor.isActive()) {
            monitor = new LogMonitor(Path.of(AppConfig.monitorLogFile()), eventService);
            monitor.start();
        }
        monitor.appendDemo("demo-user", "LOGIN_FAILURE",        "203.0.113.50", "bad password");
        Thread.sleep(150);
        monitor.appendDemo("demo-user", "LOGIN_FAILURE",        "203.0.113.50", "bad password");
        Thread.sleep(150);
        monitor.appendDemo("demo-user", "LOGIN_FAILURE",        "203.0.113.50", "bad password");
        Thread.sleep(150);
        monitor.appendDemo("demo-user", "USB_INSERTED",         "203.0.113.50", "USB drive connected");
        Thread.sleep(150);
        monitor.appendDemo("demo-user", "SENSITIVE_FILE_ACCESS","203.0.113.50", "finance/payroll.csv");
        Thread.sleep(150);
        monitor.appendDemo("demo-user", "MALWARE_DETECTED",     "203.0.113.50", "dropper.exe");
        Thread.sleep(2500);
        viewThreats();
        viewIncidents();
    }

    private void shutdown() {
        Console.info("Shutting down ARAN...");
        if (monitor != null) { monitor.stop(); audit.log("SYSTEM", "MONITOR_STOPPED"); }
        if (api != null) { api.close(); audit.log("SYSTEM", "API_STOPPED"); }
        Console.status("OK", "ARAN stopped safely.");
    }

    private static void configureLogging() {
        Logger root = Logger.getLogger("");
        for (Handler h : root.getHandlers()) root.removeHandler(h);

        ConsoleHandler ch = new ConsoleHandler();
        ch.setLevel(Level.ALL);
        ch.setFormatter(new SimpleFormatter() {
            @Override public String format(LogRecord r) {
                return String.format("[%s] %s%n", r.getLevel().getLocalizedName(), r.getMessage());
            }
        });

        root.setLevel(Level.SEVERE); // Suppress JDK noise
        Logger aranLog = Logger.getLogger("aran");
        aranLog.setLevel(Level.INFO);
        aranLog.addHandler(ch);
        aranLog.setUseParentHandlers(false);
    }
}
