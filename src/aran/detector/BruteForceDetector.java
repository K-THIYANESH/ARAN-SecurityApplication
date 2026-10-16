package aran.detector;

import aran.model.RiskAssessment;
import aran.model.SecurityEvent;
import aran.storage.EventRepository;
import aran.util.AppConfig;
import java.time.LocalDateTime;
import java.util.Optional;

public class BruteForceDetector implements ThreatDetector {
    private final EventRepository repo;
    public BruteForceDetector(EventRepository repo) { this.repo = repo; }

    @Override
    public Optional<String> detect(SecurityEvent event, RiskAssessment assessment) {
        if (!"LOGIN_FAILURE".equalsIgnoreCase(event.getEventType())) return Optional.empty();
        int threshold = AppConfig.bruteForceThreshold();
        int windowMin  = AppConfig.bruteForceWindowMin();
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(windowMin);
        long failures = repo.findAll().stream()
            .filter(e -> event.getUsername().equalsIgnoreCase(e.getUsername()))
            .filter(e -> "LOGIN_FAILURE".equalsIgnoreCase(e.getEventType()))
            .filter(e -> e.getTimestamp().isAfter(cutoff))
            .count();
        return failures >= threshold ? Optional.of("BRUTE_FORCE") : Optional.empty();
    }

    @Override public String name() { return "BruteForceDetector"; }
}
