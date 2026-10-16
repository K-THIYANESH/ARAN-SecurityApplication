package aran.model;

/**
 * Central enum for all supported security event types.
 * This is the single source of truth — all components use this enum.
 */
public enum EventType {
    LOGIN_SUCCESS("Login successful", "LOW"),
    LOGIN_FAILURE("Authentication failure", "MEDIUM"),
    FILE_ACCESS("File accessed", "LOW"),
    SENSITIVE_FILE_ACCESS("Sensitive file accessed", "HIGH"),
    USB_INSERTED("USB/Removable media inserted", "MEDIUM"),
    MALWARE_DETECTED("Malware or suspicious executable detected", "CRITICAL"),
    PRIVILEGE_ESCALATION("User privilege escalation detected", "HIGH"),
    NETWORK_SCAN("Network scan or port sweep detected", "MEDIUM"),
    DATA_EXFILTRATION("Potential data exfiltration detected", "HIGH"),
    ACCOUNT_LOCKOUT("Account locked due to failures", "MEDIUM");

    private final String description;
    private final String defaultSeverity;

    EventType(String description, String defaultSeverity) {
        this.description = description;
        this.defaultSeverity = defaultSeverity;
    }

    public String getDescription() { return description; }
    public String getDefaultSeverity() { return defaultSeverity; }

    /**
     * Parse a string into EventType, returning null if unknown.
     */
    public static EventType fromString(String value) {
        if (value == null || value.isBlank()) return null;
        try {
            return EventType.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Returns true if the string is a known event type.
     */
    public static boolean isValid(String value) {
        return fromString(value) != null;
    }
}
