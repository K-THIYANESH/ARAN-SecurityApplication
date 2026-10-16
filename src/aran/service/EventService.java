package aran.service;

import aran.model.EventType;
import aran.model.SecurityEvent;
import aran.storage.EventRepository;
import aran.util.IpValidator;
import java.util.List;
import java.util.logging.Logger;

/**
 * Event ingestion service.
 * Validates, normalizes, stores, and triggers detection on every event.
 */
public class EventService {
    private static final Logger LOG = Logger.getLogger(EventService.class.getName());

    private final EventRepository repo;
    private final ThreatDetectionService detector;
    private final AuditService audit;

    public EventService(EventRepository repo, ThreatDetectionService detector, AuditService audit) {
        this.repo = repo;
        this.detector = detector;
        this.audit = audit;
    }

    /**
     * Ingest a new security event.
     *
     * @param username  the user associated with the event (required)
     * @param eventType the event type string (must match EventType enum)
     * @param ipAddress the source IP address
     * @param source    the ingestion source (CLI, REST_API, AUTOMATIC_LOG, etc.)
     * @param details   additional free-text details
     * @return the created SecurityEvent
     * @throws IllegalArgumentException if validation fails
     */
    public SecurityEvent ingest(String username, String eventType, String ipAddress,
                                String source, String details) {
        // Validation
        if (username == null || username.isBlank())
            throw new IllegalArgumentException("Username is required");
        if (eventType == null || eventType.isBlank())
            throw new IllegalArgumentException("Event type is required");

        String normalizedType = eventType.trim().toUpperCase();
        // Warn for unknown types but still accept — system is extensible
        if (!EventType.isValid(normalizedType)) {
            LOG.warning("Unknown event type: " + normalizedType + " — accepting but not mapping to enum");
        }

        // Normalize IP — accept "unknown" when not provided
        String normalizedIp = (ipAddress == null || ipAddress.isBlank()) ? "unknown" : ipAddress.trim();
        if (!"unknown".equalsIgnoreCase(normalizedIp) && !IpValidator.isValid(normalizedIp)) {
            LOG.warning("Suspicious IP format: " + normalizedIp + " — storing as-is");
        }

        SecurityEvent event = new SecurityEvent(
            username.trim(),
            normalizedType,
            normalizedIp,
            source == null ? "UNKNOWN" : source.trim(),
            details == null ? "" : details.trim()
        );

        repo.save(event);
        audit.log(username.trim(), "EVENT_INGESTED " + normalizedType + " from=" + source);
        LOG.info("Event ingested: [" + normalizedType + "] " + username + " " + normalizedIp);

        // Trigger threat detection asynchronously to avoid blocking ingestion
        try {
            detector.analyze(event);
        } catch (Exception ex) {
            // Detection failure must not break ingestion
            LOG.severe("Threat detection failed for event " + event.getId() + ": " + ex.getMessage());
        }

        return event;
    }

    public List<SecurityEvent> all() { return repo.findAll(); }
}
