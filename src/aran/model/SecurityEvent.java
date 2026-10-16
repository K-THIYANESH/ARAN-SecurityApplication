package aran.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Represents a single security event ingested into the ARAN system.
 * Immutable once created.
 */
public class SecurityEvent {
    private static final DateTimeFormatter FMT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private final String id;
    private final LocalDateTime timestamp;
    private final String username;
    private final String eventType;
    private final String ipAddress;
    private final String source;
    private final String details;
    private final String hostname;
    private final String severity;

    public SecurityEvent(String username, String eventType, String ipAddress,
                         String source, String details) {
        this(UUID.randomUUID().toString(), LocalDateTime.now(),
             username, eventType, ipAddress, source, details,
             "unknown", severityFor(eventType));
    }

    public SecurityEvent(String id, LocalDateTime timestamp, String username,
                         String eventType, String ipAddress, String source,
                         String details, String hostname, String severity) {
        this.id = id;
        this.timestamp = timestamp;
        this.username = username;
        this.eventType = eventType;
        this.ipAddress = ipAddress;
        this.source = source;
        this.details = details;
        this.hostname = hostname;
        this.severity = severity;
    }

    // Backwards compat constructor used by old CSV loader (7-field format)
    public SecurityEvent(String id, LocalDateTime timestamp, String username,
                         String eventType, String ipAddress, String source, String details) {
        this(id, timestamp, username, eventType, ipAddress, source, details,
             "unknown", severityFor(eventType));
    }

    private static String severityFor(String eventType) {
        if (eventType == null) return "LOW";
        EventType et = EventType.fromString(eventType);
        return et != null ? et.getDefaultSeverity() : "LOW";
    }

    public String getId() { return id; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getUsername() { return username; }
    public String getEventType() { return eventType; }
    public String getIpAddress() { return ipAddress; }
    public String getSource() { return source; }
    public String getDetails() { return details; }
    public String getHostname() { return hostname; }
    public String getSeverity() { return severity; }

    /** Serialize to pipe-delimited CSV format for file storage. */
    public String toCsv() {
        return String.join("|",
            id,
            timestamp.format(FMT),
            safe(username),
            safe(eventType),
            safe(ipAddress),
            safe(source),
            safe(details),
            safe(hostname),
            safe(severity)
        );
    }

    /** Parse from CSV line (9 fields). Handles legacy 7-field format too. */
    public static SecurityEvent fromCsv(String line) {
        String[] p = line.split("\\|", -1);
        if (p.length < 7) throw new IllegalArgumentException("Too few fields: " + line);
        LocalDateTime ts = LocalDateTime.parse(p[1], FMT);
        String hostname = p.length >= 9 ? p[7] : "unknown";
        String severity  = p.length >= 9 ? p[8] : severityFor(p[3]);
        return new SecurityEvent(p[0], ts, p[2], p[3], p[4], p[5], p[6], hostname, severity);
    }

    private static String safe(String v) {
        return v == null ? "" : v.replace("|", "/").replace("\n", " ").replace("\r", "");
    }

    @Override
    public String toString() {
        return "[" + eventType + "] " + username + "@" + ipAddress + " " + timestamp;
    }
}
