package aran.util;

import java.util.regex.Pattern;

/**
 * Utility for IP address validation.
 */
public final class IpValidator {
    private static final Pattern IPV4 = Pattern.compile(
        "^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"
    );
    private static final Pattern IPV6 = Pattern.compile(
        "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    );

    private IpValidator() {}

    public static boolean isValid(String ip) {
        if (ip == null || ip.isBlank()) return false;
        if ("unknown".equalsIgnoreCase(ip.trim())) return true;
        return IPV4.matcher(ip.trim()).matches() || IPV6.matcher(ip.trim()).matches();
    }

    public static boolean isPrivate(String ip) {
        if (ip == null) return false;
        String t = ip.trim();
        return t.startsWith("10.") || t.startsWith("192.168.") ||
               t.startsWith("172.16.") || t.startsWith("172.17.") ||
               t.startsWith("172.18.") || t.startsWith("172.19.") ||
               t.startsWith("172.20.") || t.startsWith("172.21.") ||
               t.startsWith("172.22.") || t.startsWith("172.23.") ||
               t.startsWith("172.24.") || t.startsWith("172.25.") ||
               t.startsWith("172.26.") || t.startsWith("172.27.") ||
               t.startsWith("172.28.") || t.startsWith("172.29.") ||
               t.startsWith("172.30.") || t.startsWith("172.31.") ||
               t.startsWith("127.") || "localhost".equalsIgnoreCase(t);
    }
}
