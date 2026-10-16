package aran.model;

public enum RiskLevel {
    LOW, MEDIUM, HIGH, CRITICAL;

    public static RiskLevel fromScore(int score) {
        if (score >= 80) return CRITICAL;
        if (score >= 60) return HIGH;
        if (score >= 30) return MEDIUM;
        return LOW;
    }
}
