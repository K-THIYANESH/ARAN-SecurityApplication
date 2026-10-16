package aran.service;

import aran.model.*;
import aran.storage.EventRepository;
import aran.util.AppConfig;
import aran.util.IpValidator;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Calculates a 0-100 risk score for a SecurityEvent.
 * Score is deterministic and fully explained.
 *
 * Formula:
 *   score = baseScore(eventType)
 *         + repeatedLoginFailureBonus
 *         + sensitiveResourceBonus
 *         + removableMediaBonus
 *         + privilegeEscalationBonus
 *         - privateIpDiscount
 *   capped at 100
 */
public class RiskScoreService {
    private final EventRepository repo;

    public RiskScoreService(EventRepository repo) {
        this.repo = repo;
    }

    public RiskAssessment assess(SecurityEvent e) {
        int score = baseScore(e.getEventType());
        StringBuilder why = new StringBuilder("Base: " + e.getEventType() + " (" + score + ")");

        // Bonus: repeated login failures in time window
        int bruteWindow = AppConfig.bruteForceWindowMin();
        int bruteThreshold = AppConfig.bruteForceThreshold();
        long recentFailures = countRecentFailures(e.getUsername(), bruteWindow);
        if (recentFailures >= bruteThreshold) {
            int bonus = 30;
            score += bonus;
            why.append("; +" + bonus + " repeated login failures (" + recentFailures + " in " + bruteWindow + "min)");
        }

        // Bonus: sensitive file access
        if ("SENSITIVE_FILE_ACCESS".equalsIgnoreCase(e.getEventType())) {
            int bonus = 15;
            score += bonus;
            why.append("; +" + bonus + " sensitive resource access");
        }

        // Bonus: USB / removable media
        if ("USB_INSERTED".equalsIgnoreCase(e.getEventType())) {
            int bonus = 10;
            score += bonus;
            why.append("; +" + bonus + " removable media");
        }

        // Bonus: privilege escalation
        if ("PRIVILEGE_ESCALATION".equalsIgnoreCase(e.getEventType())) {
            int bonus = 20;
            score += bonus;
            why.append("; +" + bonus + " privilege escalation");
        }

        // Bonus: malware
        if ("MALWARE_DETECTED".equalsIgnoreCase(e.getEventType())) {
            int bonus = 10;
            score += bonus;
            why.append("; +" + bonus + " malware detected");
        }

        // Discount: private/trusted IP
        if (e.getIpAddress() != null && IpValidator.isPrivate(e.getIpAddress())) {
            int discount = 5;
            score = Math.max(0, score - discount);
            why.append("; -" + discount + " private IP");
        }

        score = Math.min(100, score);
        RiskLevel level = RiskLevel.fromScore(score);
        return new RiskAssessment(score, level, why.toString());
    }

    private long countRecentFailures(String username, int windowMinutes) {
        LocalDateTime cutoff = LocalDateTime.now().minusMinutes(windowMinutes);
        return repo.findAll().stream()
            .filter(x -> username.equalsIgnoreCase(x.getUsername()))
            .filter(x -> "LOGIN_FAILURE".equalsIgnoreCase(x.getEventType()))
            .filter(x -> x.getTimestamp().isAfter(cutoff))
            .count();
    }

    private static int baseScore(String type) {
        if (type == null) return 10;
        return switch (type.toUpperCase()) {
            case "MALWARE_DETECTED"     -> 75;
            case "PRIVILEGE_ESCALATION" -> 60;
            case "SENSITIVE_FILE_ACCESS"-> 35;
            case "DATA_EXFILTRATION"    -> 55;
            case "NETWORK_SCAN"         -> 30;
            case "USB_INSERTED"         -> 20;
            case "LOGIN_FAILURE"        -> 20;
            case "ACCOUNT_LOCKOUT"      -> 25;
            case "FILE_ACCESS"          -> 10;
            case "LOGIN_SUCCESS"        -> 5;
            default                     -> 10;
        };
    }
}
