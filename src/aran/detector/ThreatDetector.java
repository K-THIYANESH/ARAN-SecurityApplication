package aran.detector;

import aran.model.RiskAssessment;
import aran.model.SecurityEvent;
import java.util.Optional;

public interface ThreatDetector {
    Optional<String> detect(SecurityEvent event, RiskAssessment assessment);
    String name();
}
