package aran.model;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Security incident derived from a high/critical threat.
 * Lifecycle: OPEN → INVESTIGATING → CONTAINED → RESOLVED
 */
public class Incident {
    public enum Status { OPEN, INVESTIGATING, CONTAINED, RESOLVED }

    private final String id;
    private final String threatId;
    private final String title;
    private final int riskScore;
    private volatile Status status;
    private final LocalDateTime createdAt;
    private volatile LocalDateTime updatedAt;

    public Incident(String threatId, String title, int riskScore) {
        this("INC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
             threatId, title, riskScore, Status.OPEN,
             LocalDateTime.now(), LocalDateTime.now());
    }

    /** Reconstruction constructor used when loading persisted incidents. */
    public Incident(String id, String threatId, String title, int riskScore,
                     Status status, LocalDateTime createdAt, LocalDateTime updatedAt) {
        this.id = id;
        this.threatId = threatId;
        this.title = title;
        this.riskScore = riskScore;
        this.status = status;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public String getId() { return id; }
    public String getThreatId() { return threatId; }
    public String getTitle() { return title; }
    public int getRiskScore() { return riskScore; }
    public Status getStatus() { return status; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }

    public synchronized void setStatus(Status newStatus) {
        this.status = newStatus;
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * Parse a status string. Throws IllegalArgumentException for unknown values.
     */
    public static Status parseStatus(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Status is required");
        try {
            return Status.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid status '" + value + "'. Valid values: OPEN, INVESTIGATING, CONTAINED, RESOLVED");
        }
    }

    private static final java.time.format.DateTimeFormatter FMT =
        java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    /** Serialize to pipe-delimited CSV for file persistence. */
    public synchronized String toCsv() {
        return String.join("|",
            id, safe(threatId), safe(title), String.valueOf(riskScore),
            status.name(), createdAt.format(FMT), updatedAt.format(FMT));
    }

    /** Parse an incident back from its persisted CSV line. */
    public static Incident fromCsv(String line) {
        String[] p = line.split("\\|", -1);
        if (p.length < 7) throw new IllegalArgumentException("Too few fields: " + line);
        return new Incident(p[0], p[1], p[2], Integer.parseInt(p[3]),
            Status.valueOf(p[4]), LocalDateTime.parse(p[5], FMT), LocalDateTime.parse(p[6], FMT));
    }

    private static String safe(String v) {
        return v == null ? "" : v.replace("|", "/").replace("\n", " ").replace("\r", "");
    }
}
