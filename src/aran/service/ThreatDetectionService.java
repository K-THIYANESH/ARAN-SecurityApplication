package aran.service;

import aran.detector.*;
import aran.model.*;
import aran.storage.*;
import aran.util.AppConfig;
import java.util.*;
import java.util.logging.Logger;

/**
 * Central threat detection engine.
 * Runs each SecurityEvent through a pipeline of specialized detectors.
 * Creates Threat and Incident records when threats are found.
 *
 * Pipeline:
 *   SecurityEvent → [detectors] → RiskAssessment → Threat → (Incident if HIGH/CRITICAL)
 */
public class ThreatDetectionService {
    private static final Logger LOG = Logger.getLogger(ThreatDetectionService.class.getName());

    private final EventRepository events;
    private final ThreatRepository threats;
    private final IncidentRepository incidents;
    private final RiskScoreService riskEngine;
    private final AuditService audit;
    private final List<ThreatDetector> detectors;

    public ThreatDetectionService(EventRepository events, ThreatRepository threats,
                                   IncidentRepository incidents, AuditService audit) {
        this.events = events;
        this.threats = threats;
        this.incidents = incidents;
        this.audit = audit;
        this.riskEngine = new RiskScoreService(events);

        // Order matters: more specific detectors first
        this.detectors = List.of(
            new MalwareDetector(),
            new BruteForceDetector(events),
            new PrivilegeEscalationDetector(),
            new SensitiveFileDetector(),
            new BehaviourAnalyzer(events)
        );
    }

    /**
     * Analyze a security event through all detectors.
     * Returns the created Threat if one was found, otherwise empty.
     */
    public Optional<Threat> analyze(SecurityEvent event) {
        // Step 1: Calculate risk score
        RiskAssessment assessment = riskEngine.assess(event);

        // Step 2: Run each detector, use first match
        String threatType = null;
        for (ThreatDetector detector : detectors) {
            Optional<String> result = detector.detect(event, assessment);
            if (result.isPresent()) {
                threatType = result.get();
                LOG.fine("Detector " + detector.name() + " matched: " + threatType);
                break;
            }
        }

        // Step 3: Skip LOW events with no detected threat
        if (threatType == null && assessment.level() == RiskLevel.LOW) {
            return Optional.empty();
        }

        if (threatType == null) {
            threatType = "SUSPICIOUS_ACTIVITY";
        }

        // Step 4: Create Threat record
        Threat threat = new Threat(
            event.getId(),
            threatType,
            assessment.level().name(),
            assessment.score(),
            assessment.explanation()
        );
        threats.save(threat);
        audit.log("SYSTEM", "THREAT_DETECTED " + threatType + " risk=" + assessment.score());
        LOG.info("Threat detected: " + threatType + " [" + assessment.level() + "] score=" + assessment.score());

        // Step 5: Create Incident for HIGH and CRITICAL threats
        int highThreshold = AppConfig.riskHighThreshold();
        if (assessment.score() >= highThreshold) {
            String incidentTitle = formatIncidentTitle(threatType, event);
            Incident incident = new Incident(threat.getId(), incidentTitle, assessment.score());
            incidents.save(incident);
            audit.log("SYSTEM", "INCIDENT_CREATED " + incident.getId() + " [" + incidentTitle + "]");
            LOG.info("Incident created: " + incident.getId() + " for threat " + threatType);
        }

        return Optional.of(threat);
    }

    private String formatIncidentTitle(String threatType, SecurityEvent event) {
        return switch (threatType) {
            case "BRUTE_FORCE"          -> "Brute Force Attack on " + event.getUsername();
            case "MALWARE"              -> "Malware Detected on " + event.getIpAddress();
            case "PRIVILEGE_ESCALATION" -> "Privilege Escalation by " + event.getUsername();
            case "SUSPICIOUS_FILE_ACCESS" -> "Suspicious File Access by " + event.getUsername();
            case "POTENTIAL_DATA_THEFT" -> "Potential Data Theft by " + event.getUsername();
            case "DATA_EXFILTRATION"    -> "Data Exfiltration Detected";
            default                     -> "Security Incident: " + threatType.replace('_', ' ');
        };
    }
}
