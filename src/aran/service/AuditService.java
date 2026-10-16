package aran.service;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.util.logging.Logger;

/**
 * Writes immutable audit log entries to logs/audit.log.
 * Called for all significant system events.
 */
public class AuditService {
    private static final Logger LOG = Logger.getLogger(AuditService.class.getName());
    private final Path file;

    public AuditService() {
        this(Path.of("logs/audit.log"));
    }

    public AuditService(Path file) {
        this.file = file;
        try { Files.createDirectories(file.getParent()); }
        catch (IOException e) { LOG.warning("Cannot create audit log dir: " + e.getMessage()); }
    }

    /**
     * Write an audit entry. Synchronized to prevent interleaving.
     */
    public synchronized void log(String actor, String action) {
        String entry = LocalDateTime.now() + " | " + safeStr(actor) + " | " + safeStr(action);
        try (BufferedWriter w = Files.newBufferedWriter(file,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            w.write(entry);
            w.newLine();
        } catch (IOException e) {
            // Audit failures should be visible — never silently swallowed
            LOG.severe("AUDIT LOG FAILURE: " + entry + " | Error: " + e.getMessage());
        }
    }

    private static String safeStr(String s) {
        return s == null ? "" : s.replace("\n", " ").replace("\r", "");
    }
}
