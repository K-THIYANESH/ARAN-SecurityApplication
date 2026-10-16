package aran.ml;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lightweight 3-class ML classifier for uploaded security logs.
 * Model: multinomial logistic regression trained offline and stored as JSON.
 * Runtime has zero external ML dependencies.
 */
public class MLLogClassifier {
    public enum Decision { SAFE, MANUAL_REVIEW, BLOCK }

    public record Result(Decision decision, double confidence,
                         double safeProbability, double reviewProbability,
                         double blockProbability, boolean modelUsed,
                         String explanation) {}

    private static final String[] EVENT_TYPES = {
        "LOGIN_SUCCESS","LOGIN_FAILURE","FILE_ACCESS","SENSITIVE_FILE_ACCESS",
        "USB_INSERTED","MALWARE_DETECTED","PRIVILEGE_ESCALATION",
        "NETWORK_SCAN","DATA_EXFILTRATION","ACCOUNT_LOCKOUT"
    };
    private static final String[] KEYWORDS = {
        "bad password","invalid password","finance","payroll","usb","dropper",
        "malware","ransomware","powershell","encoded","credential","password",
        "shadow","passwd","exfil","upload","outbound","port scan","privilege",
        "admin","suspicious","known malicious"
    };

    private final double[][] weights;
    private final double[] intercepts;
    private final double blockThreshold;
    private final double reviewThreshold;

    public MLLogClassifier(Path modelPath) throws IOException {
        String json = Files.readString(modelPath, StandardCharsets.UTF_8);
        this.weights = parseMatrix(json, "weights");
        this.intercepts = parseVector(json, "intercepts");
        this.blockThreshold = parseNumber(json, "block", 0.65);
        this.reviewThreshold = parseNumber(json, "manualReview", 0.50);
        if (weights.length != 3 || intercepts.length != 3 || weights[0].length != featureCount()) {
            throw new IOException("Invalid ML model dimensions");
        }
    }

    public static int featureCount() {
        return EVENT_TYPES.length + KEYWORDS.length + 5;
    }

    public Result classify(String eventType, String details, String ip,
                           int loginFailures, boolean usbBeforeSensitive, int repeatIp) {
        double[] x = features(eventType, details, ip, loginFailures, usbBeforeSensitive, repeatIp);
        double[] logits = new double[3];
        for (int c = 0; c < 3; c++) {
            double z = intercepts[c];
            for (int j = 0; j < x.length; j++) z += weights[c][j] * x[j];
            logits[c] = z;
        }

        // Numerically stable softmax.
        double max = Math.max(logits[0], Math.max(logits[1], logits[2]));
        double s0 = Math.exp(logits[0] - max);
        double s1 = Math.exp(logits[1] - max);
        double s2 = Math.exp(logits[2] - max);
        double sum = s0 + s1 + s2;
        double p0 = s0 / sum, p1 = s1 / sum, p2 = s2 / sum;

        Decision d;
        double confidence;
        if (p2 >= blockThreshold) {
            d = Decision.BLOCK; confidence = p2;
        } else if (p1 >= reviewThreshold || p1 >= p0 && p1 >= p2) {
            d = Decision.MANUAL_REVIEW; confidence = p1;
        } else {
            d = Decision.SAFE; confidence = p0;
        }

        String explanation = switch (d) {
            case SAFE -> "ML model found a low-risk event pattern.";
            case MANUAL_REVIEW -> "ML model found a potentially suspicious pattern requiring analyst review.";
            case BLOCK -> "ML model found a high-risk pattern matching a containment condition.";
        };
        return new Result(d, confidence, p0, p1, p2, true, explanation);
    }

    /**
     * Deterministic safety fallback. It is used when the model is missing,
     * unreadable, malformed, or inference fails.
     */
    public static Result fallback(String eventType, String details) {
        String t = eventType == null ? "" : eventType.toUpperCase(Locale.ROOT);
        String d = details == null ? "" : details.toLowerCase(Locale.ROOT);
        Decision decision;
        String why;

        if (Set.of("MALWARE_DETECTED","DATA_EXFILTRATION","PRIVILEGE_ESCALATION").contains(t)
                || d.contains("ransomware") || d.contains("known malicious")
                || d.contains("credential exfil")) {
            decision = Decision.BLOCK;
            why = "Fallback rules matched a high-confidence containment condition.";
        } else if (Set.of("LOGIN_FAILURE","SENSITIVE_FILE_ACCESS","USB_INSERTED",
                          "NETWORK_SCAN","ACCOUNT_LOCKOUT").contains(t)
                || d.contains("suspicious") || d.contains("encoded")) {
            decision = Decision.MANUAL_REVIEW;
            why = "Fallback rules matched an event that requires analyst review.";
        } else if (Set.of("LOGIN_SUCCESS","FILE_ACCESS").contains(t)) {
            decision = Decision.SAFE;
            why = "Fallback rules matched a normal event pattern.";
        } else {
            decision = Decision.MANUAL_REVIEW;
            why = "Unknown event pattern is conservatively routed to manual review.";
        }

        double safe = decision == Decision.SAFE ? 1.0 : 0.0;
        double review = decision == Decision.MANUAL_REVIEW ? 1.0 : 0.0;
        double block = decision == Decision.BLOCK ? 1.0 : 0.0;
        return new Result(decision, 1.0, safe, review, block, false, why);
    }

    private static double[] features(String eventType, String details, String ip,
                                     int failures, boolean usbBeforeSensitive, int repeatIp) {
        String t = eventType == null ? "" : eventType.trim().toUpperCase(Locale.ROOT);
        String d = details == null ? "" : details.toLowerCase(Locale.ROOT);
        double[] x = new double[featureCount()];
        int k = 0;

        for (String et : EVENT_TYPES) x[k++] = et.equals(t) ? 1.0 : 0.0;
        for (String kw : KEYWORDS) x[k++] = d.contains(kw) ? 1.0 : 0.0;

        x[k++] = isExternalIp(ip) ? 1.0 : 0.0;
        x[k++] = Math.min(Math.max(failures, 0), 10) / 10.0;
        x[k++] = usbBeforeSensitive ? 1.0 : 0.0;
        x[k++] = Math.min(Math.max(repeatIp, 0), 10) / 10.0;
        x[k]   = Math.min(d.length(), 300) / 300.0;
        return x;
    }

    private static boolean isExternalIp(String ip) {
        if (ip == null || ip.isBlank() || "unknown".equalsIgnoreCase(ip)) return false;
        String s = ip.trim();
        if (s.startsWith("10.") || s.startsWith("192.168.") || s.startsWith("127.")) return false;
        if (s.startsWith("172.")) {
            try {
                int second = Integer.parseInt(s.split("\\.")[1]);
                if (second >= 16 && second <= 31) return false;
            } catch (Exception ignored) {}
        }
        return true;
    }

    private static double[] parseVector(String json, String key) throws IOException {
        String body = arrayBody(json, key);
        String[] parts = body.split(",");
        double[] out = new double[parts.length];
        for (int i=0;i<parts.length;i++) out[i] = Double.parseDouble(parts[i].trim());
        return out;
    }

    private static double[][] parseMatrix(String json, String key) throws IOException {
        String body = arrayBody(json, key);
        List<double[]> rows = new ArrayList<>();
        Matcher m = Pattern.compile("\\[([^\\[\\]]+)\\]").matcher(body);
        while (m.find()) {
            String[] parts = m.group(1).split(",");
            double[] row = new double[parts.length];
            for (int i=0;i<parts.length;i++) row[i] = Double.parseDouble(parts[i].trim());
            rows.add(row);
        }
        if (rows.isEmpty()) throw new IOException("Missing matrix: " + key);
        return rows.toArray(new double[0][]);
    }

    private static String arrayBody(String json, String key) throws IOException {
        int keyPos = json.indexOf("\"" + key + "\"");
        if (keyPos < 0) throw new IOException("Missing model key: " + key);
        int start = json.indexOf('[', keyPos);
        if (start < 0) throw new IOException("Missing array for: " + key);
        int depth = 0;
        for (int i=start;i<json.length();i++) {
            char c=json.charAt(i);
            if (c=='[') depth++;
            else if (c==']') {
                depth--;
                if (depth==0) return json.substring(start+1,i);
            }
        }
        throw new IOException("Unclosed array: " + key);
    }

    private static double parseNumber(String json, String key, double fallback) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*([0-9.]+)").matcher(json);
        return m.find() ? Double.parseDouble(m.group(1)) : fallback;
    }
}
