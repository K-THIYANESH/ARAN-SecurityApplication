package aran.monitor;

import aran.service.EventService;
import java.io.*;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.logging.Logger;

/**
 * Automatic log file monitor.
 * Watches a file for new lines and ingests them as security events.
 *
 * Log format (pipe-delimited):
 *   username|eventType|ipAddress|details
 *
 * Example:
 *   admin|LOGIN_FAILURE|203.0.113.10|invalid password
 *
 * Handles:
 * - File not found: waits and retries
 * - Malformed lines: logs and skips
 * - Empty lines: silently skips
 * - Blank/unknown event types: warns and skips
 * - File becoming unavailable: logs and continues polling
 */
public class LogMonitor implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(LogMonitor.class.getName());

    private final Path file;
    private final EventService service;
    private final int intervalMs;
    private volatile boolean running;
    private ExecutorService executor;
    private volatile long lastPosition = 0;
    private volatile boolean active = false;

    public LogMonitor(Path file, EventService service, int intervalMs) {
        this.file = file;
        this.service = service;
        this.intervalMs = intervalMs;
    }

    public LogMonitor(Path file, EventService service) {
        this(file, service, 1000);
    }

    public void start() throws IOException {
        if (running) return;
        running = true;
        Files.createDirectories(file.getParent());
        if (!Files.exists(file)) Files.createFile(file);
        lastPosition = Files.size(file); // Start at end — don't replay history

        executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "aran-log-monitor");
            t.setDaemon(true);
            return t;
        });

        executor.submit(this::monitorLoop);
        active = true;
        LOG.info("Log monitor started on: " + file.toAbsolutePath());
    }

    private void monitorLoop() {
        while (running) {
            try {
                if (!Files.exists(file)) {
                    LOG.warning("Monitored log file not found: " + file + " — waiting...");
                    Thread.sleep(intervalMs * 5L);
                    continue;
                }
                long currentSize = Files.size(file);
                if (currentSize < lastPosition) {
                    // File was truncated/rotated
                    LOG.info("Log file was rotated/truncated, resetting position.");
                    lastPosition = 0;
                }
                if (currentSize > lastPosition) {
                    try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
                        raf.seek(lastPosition);
                        String line;
                        while ((line = raf.readLine()) != null) {
                            lastPosition = raf.getFilePointer();
                            if (!line.isBlank()) {
                                processLine(line.trim());
                            }
                        }
                    }
                }
                Thread.sleep(intervalMs);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception ex) {
                LOG.severe("Log monitor error: " + ex.getMessage());
                try { Thread.sleep(intervalMs * 3L); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
            }
        }
        active = false;
        LOG.info("Log monitor stopped.");
    }

    private void processLine(String line) {
        try {
            String[] parts = line.split("\\|", 4);
            if (parts.length < 3) {
                LOG.warning("Malformed log line (expected username|eventType|ip[|details]): " + line);
                return;
            }
            String username = parts[0].trim();
            String eventType = parts[1].trim();
            String ip        = parts[2].trim();
            String details   = parts.length == 4 ? parts[3].trim() : "";

            if (username.isEmpty() || eventType.isEmpty()) {
                LOG.warning("Log line missing required fields: " + line);
                return;
            }

            service.ingest(username, eventType, ip, "AUTOMATIC_LOG", details);
            LOG.fine("Auto-ingested from log: " + eventType + " user=" + username);
        } catch (IllegalArgumentException ex) {
            LOG.warning("Rejected log line [" + ex.getMessage() + "]: " + line);
        } catch (Exception ex) {
            LOG.severe("Failed processing log line: " + line + " | " + ex.getMessage());
        }
    }

    /**
     * Append a demo event to the monitored log file (for simulation/testing).
     */
    public void appendDemo(String user, String type, String ip, String details) throws IOException {
        Files.createDirectories(file.getParent());
        String line = String.join("|", user, type, ip, details) + System.lineSeparator();
        Files.writeString(file, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    public boolean isActive() { return running && active; }
    public Path getLogFile() { return file; }

    public void stop() {
        running = false;
        active = false;
        if (executor != null) {
            executor.shutdownNow();
            try { executor.awaitTermination(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        }
    }

    @Override public void close() { stop(); }
}
