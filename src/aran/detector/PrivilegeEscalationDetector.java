package aran.detector;

import aran.model.RiskAssessment;
import aran.model.SecurityEvent;
import java.util.Optional;

public class PrivilegeEscalationDetector implements ThreatDetector {
    @Override
    public Optional<String> detect(SecurityEvent event, RiskAssessment assessment) {
        if ("PRIVILEGE_ESCALATION".equalsIgnoreCase(event.getEventType()))
            return Optional.of("PRIVILEGE_ESCALATION");
        return Optional.empty();
    }
    @Override public String name() { return "PrivilegeEscalationDetector"; }
}
