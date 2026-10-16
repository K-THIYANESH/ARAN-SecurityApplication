package aran.ml;

import aran.model.SecurityEvent;
import aran.service.EventService;

import java.nio.file.Path;
import java.util.*;

/**
 * Parses uploaded pipe-delimited security logs, classifies each line with the
 * lightweight ML model, then sends accepted events through ARAN's existing
 * threat-detection pipeline. If ML is unavailable, deterministic fallback rules
 * keep the analyzer operational.
 */
public class MLLogAnalyzerService {
    public record LineResult(int lineNumber, String raw, String username, String eventType,
                             String ipAddress, String details, String eventId,
                             MLLogClassifier.Result classification, String error) {}

    public record BatchResult(String filename, int totalLines, int validLines, int rejectedLines,
                              int safe, int manualReview, int blocked,
                              boolean modelAvailable, List<LineResult> results) {}

    private final EventService eventService;
    private final MLLogClassifier model;

    public MLLogAnalyzerService(EventService eventService, Path modelPath) {
        this.eventService = eventService;
        MLLogClassifier loaded = null;
        try { loaded = new MLLogClassifier(modelPath); }
        catch (Exception ignored) {}
        this.model = loaded;
    }

    public boolean isModelAvailable() { return model != null; }

    public BatchResult analyze(String filename, String content) {
        if (content == null) content = "";
        String[] lines = content.replace("\r\n","\n").replace('\r','\n').split("\n", -1);

        Map<String,Integer> failures = new HashMap<>();
        Map<String,Boolean> usb = new HashMap<>();
        Map<String,Integer> ipCounts = new HashMap<>();
        List<LineResult> results = new ArrayList<>();
        int valid=0, rejected=0, safe=0, review=0, blocked=0;

        for (int i=0;i<lines.length;i++) {
            String raw = lines[i].trim();
            if (raw.isEmpty() || raw.startsWith("#")) continue;

            String[] p = raw.split("\\|",4);
            if (p.length < 3 || p[0].trim().isEmpty() || p[1].trim().isEmpty()) {
                rejected++;
                results.add(new LineResult(i+1, raw, "", "", "", "", null,
                    MLLogClassifier.fallback("", raw), "Expected username|eventType|ipAddress|details"));
                continue;
            }

            String username=p[0].trim();
            String type=p[1].trim().toUpperCase(Locale.ROOT);
            String ip=p[2].trim().isEmpty() ? "unknown" : p[2].trim();
            String details=p.length==4 ? p[3].trim() : "";

            String userKey=username.toLowerCase(Locale.ROOT);
            String ipKey=ip.toLowerCase(Locale.ROOT);
            int failureCount=failures.getOrDefault(userKey,0);
            boolean usbBefore=usb.getOrDefault(userKey,false);
            int repeatIp=ipCounts.getOrDefault(ipKey,0);

            MLLogClassifier.Result c;
            try {
                c = model != null
                    ? model.classify(type,details,ip,failureCount,usbBefore,repeatIp)
                    : MLLogClassifier.fallback(type,details);
            } catch (Exception ex) {
                c = MLLogClassifier.fallback(type,details);
            }

            String eventId=null;
            String error=null;
            try {
                SecurityEvent event=eventService.ingest(username,type,ip,"ML_UPLOAD",details);
                eventId=event.getId();
                valid++;
            } catch (Exception ex) {
                error=ex.getMessage();
                rejected++;
            }

            switch(c.decision()) {
                case SAFE -> safe++;
                case MANUAL_REVIEW -> review++;
                case BLOCK -> blocked++;
            }
            results.add(new LineResult(i+1,raw,username,type,ip,details,eventId,c,error));

            if ("LOGIN_FAILURE".equals(type)) failures.put(userKey,failureCount+1);
            if ("USB_INSERTED".equals(type)) usb.put(userKey,true);
            if ("SENSITIVE_FILE_ACCESS".equals(type)) usb.put(userKey,false);
            ipCounts.put(ipKey,repeatIp+1);
        }

        return new BatchResult(filename, lines.length, valid, rejected, safe, review, blocked,
                               model != null, results);
    }
}
