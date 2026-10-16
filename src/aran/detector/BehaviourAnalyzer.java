package aran.detector;

import aran.model.RiskAssessment;
import aran.model.RiskLevel;
import aran.model.SecurityEvent;
import aran.storage.EventRepository;
import java.time.LocalDateTime;
import java.util.Optional;

public class BehaviourAnalyzer implements ThreatDetector {
    private final EventRepository repo;
    public BehaviourAnalyzer(EventRepository repo) { this.repo = repo; }

    @Override
    public Optional<String> detect(SecurityEvent event, RiskAssessment assessment) {
        String type = event.getEventType().toUpperCase();
        // USB + sensitive file access within 10 min → potential data theft
        if ("SENSITIVE_FILE_ACCESS".equals(type)) {
            LocalDateTime tenMinAgo = event.getTimestamp().minusMinutes(10);
            boolean recentUsb = repo.findAll().stream()
                .filter(e -> event.getUsername().equalsIgnoreCase(e.getUsername()))
                .filter(e -> "USB_INSERTED".equalsIgnoreCase(e.getEventType()))
                .anyMatch(e -> e.getTimestamp().isAfter(tenMinAgo) &&
                               e.getTimestamp().isBefore(event.getTimestamp().plusSeconds(1)));
            if (recentUsb) return Optional.of("POTENTIAL_DATA_THEFT");
        }
        if ("DATA_EXFILTRATION".equals(type)) return Optional.of("DATA_EXFILTRATION");
        return Optional.empty();
    }

    @Override public String name() { return "BehaviourAnalyzer"; }
}
