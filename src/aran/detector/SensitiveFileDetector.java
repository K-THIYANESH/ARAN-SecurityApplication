package aran.detector;

import aran.model.RiskAssessment;
import aran.model.SecurityEvent;
import java.util.Optional;

public class SensitiveFileDetector implements ThreatDetector {
    @Override
    public Optional<String> detect(SecurityEvent event, RiskAssessment assessment) {
        if ("SENSITIVE_FILE_ACCESS".equalsIgnoreCase(event.getEventType()))
            return Optional.of("SUSPICIOUS_FILE_ACCESS");
        return Optional.empty();
    }
    @Override public String name() { return "SensitiveFileDetector"; }
}
