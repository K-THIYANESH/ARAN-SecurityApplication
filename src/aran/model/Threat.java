package aran.model;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * A threat finding produced by the ARAN detection engine.
 * Immutable once created.
 */
public class Threat {
    private final String id;
    private final String eventId;
    private final String type;
    private final String severity;
    private final int riskScore;
    private final String explanation;
    private final LocalDateTime detectedAt;

    public Threat(String eventId, String type, String severity,
                  int riskScore, String explanation) {
        this(UUID.randomUUID().toString(), eventId, type, severity, riskScore,
             explanation, LocalDateTime.now());
    }

    /** Reconstruction constructor used when loading persisted threats. */
    public Threat(String id, String eventId, String type, String severity,
                  int riskScore, String explanation, LocalDateTime detectedAt) {
        this.id = id;
        this.eventId = eventId;
        this.type = type;
        this.severity = severity;
        this.riskScore = riskScore;
        this.explanation = explanation;
        this.detectedAt = detectedAt;
    }

    public String getId() { return id; }
    public String getEventId() { return eventId; }
    public String getType() { return type; }
    public String getSeverity() { return severity; }
    public int getRiskScore() { return riskScore; }
    public String getExplanation() { return explanation; }
    public LocalDateTime getDetectedAt() { return detectedAt; }

    private static final java.time.format.DateTimeFormatter FMT =
        java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    /** Serialize to pipe-delimited CSV for file persistence. */
    public String toCsv() {
        return String.join("|",
            id, safe(eventId), safe(type), safe(severity),
            String.valueOf(riskScore), safe(explanation), detectedAt.format(FMT));
    }

    /** Parse a threat back from its persisted CSV line. */
    public static Threat fromCsv(String line) {
        String[] p = line.split("\\|", -1);
        if (p.length < 7) throw new IllegalArgumentException("Too few fields: " + line);
        return new Threat(p[0], p[1], p[2], p[3],
            Integer.parseInt(p[4]), p[5], LocalDateTime.parse(p[6], FMT));
    }

    private static String safe(String v) {
        return v == null ? "" : v.replace("|", "/").replace("\n", " ").replace("\r", "");
    }
}
