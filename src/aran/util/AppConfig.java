package aran.util;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * Centralized configuration loaded from config/application.properties.
 * All runtime settings are accessed through this class.
 */
public final class AppConfig {
    private static final Properties P = new Properties();

    static {
        Path path = Path.of("config/application.properties");
        if (Files.exists(path)) {
            try (Reader r = Files.newBufferedReader(path)) {
                P.load(r);
            } catch (IOException e) {
                System.err.println("[WARN] Could not load config: " + e.getMessage());
            }
        } else {
            System.err.println("[WARN] config/application.properties not found, using defaults.");
        }
    }

    private AppConfig() {}

    public static String get(String key, String fallback) {
        return P.getProperty(key, fallback);
    }

    public static int getInt(String key, int fallback) {
        String val = P.getProperty(key);
        if (val == null) return fallback;
        try { return Integer.parseInt(val.trim()); }
        catch (NumberFormatException e) { return fallback; }
    }

    public static boolean getBool(String key, boolean fallback) {
        String val = P.getProperty(key);
        if (val == null) return fallback;
        return Boolean.parseBoolean(val.trim());
    }

    public static long getLong(String key, long fallback) {
        String val = P.getProperty(key);
        if (val == null) return fallback;
        try { return Long.parseLong(val.trim()); }
        catch (NumberFormatException e) { return fallback; }
    }

    // Convenience accessors for common settings
    public static int apiPort()            { return getInt("api.port", 8080); }
    public static String storageMode()     { return get("storage.mode", "FILE"); }
    public static String dbUrl()           { return get("db.url", "jdbc:mysql://localhost:3306/aran"); }
    public static String dbUser()          { return get("db.user", "root"); }
    public static String dbPassword()      { return get("db.password", ""); }
    public static String monitorLogFile()  { return get("monitor.log.file", "logs/security-events.log"); }
    public static int monitorIntervalMs()  { return getInt("monitor.interval.ms", 1000); }
    public static int bruteForceThreshold(){ return getInt("bruteforce.threshold", 3); }
    public static int bruteForceWindowMin(){ return getInt("bruteforce.window.minutes", 5); }
    public static int riskHighThreshold()  { return getInt("risk.threshold.high", 60); }
    public static int riskCriticalThreshold(){ return getInt("risk.threshold.critical", 80); }
}
