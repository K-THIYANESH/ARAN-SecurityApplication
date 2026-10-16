package aran.util;

/**
 * ANSI-coloured console output for CLI usage.
 */
public final class Console {
    public static final String RESET  = "\033[0m";
    public static final String CYAN   = "\033[36m";
    public static final String GREEN  = "\033[32m";
    public static final String YELLOW = "\033[33m";
    public static final String RED    = "\033[31m";
    public static final String BOLD   = "\033[1m";

    private Console() {}

    public static void header(String s) {
        System.out.println("\n" + BOLD + CYAN + "═".repeat(60) + RESET);
        System.out.println(BOLD + CYAN + "  " + s + RESET);
        System.out.println(CYAN + "═".repeat(60) + RESET);
    }

    public static void status(String level, String s) {
        String c = switch (level.toUpperCase()) {
            case "CRITICAL" -> RED + BOLD;
            case "HIGH"     -> RED;
            case "MEDIUM"   -> YELLOW;
            case "OK", "LOW"-> GREEN;
            default          -> RESET;
        };
        System.out.println(c + "[" + level + "] " + RESET + s);
    }

    public static void info(String s)  { System.out.println(CYAN + "[INFO] " + RESET + s); }
    public static void warn(String s)  { System.out.println(YELLOW + "[WARN] " + RESET + s); }
    public static void error(String s) { System.out.println(RED + "[ERROR] " + RESET + s); }
}
