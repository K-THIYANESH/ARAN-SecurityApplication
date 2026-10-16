package aran.service;

import aran.model.*;
import aran.storage.*;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.logging.Logger;

/**
 * Generates security operations reports as text files in the reports/ directory.
 */
public class ReportService {
    private static final Logger LOG = Logger.getLogger(ReportService.class.getName());

    private final EventRepository events;
    private final ThreatRepository threats;
    private final IncidentRepository incidents;
    private final AuditService audit;

    public ReportService(EventRepository events, ThreatRepository threats,
                         IncidentRepository incidents, AuditService audit) {
        this.events = events;
        this.threats = threats;
        this.incidents = incidents;
        this.audit = audit;
    }

    /**
     * Generate a full security operations report.
     * @return the path to the generated report file
     */
    public Path generate() throws IOException {
        Path dir = Path.of("reports");
        Files.createDirectories(dir);
        String timestamp = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss").format(LocalDateTime.now());
        Path reportPath = dir.resolve("ARAN-report-" + timestamp + ".txt");

        List<aran.model.Threat> threatList = threats.findAll();
        List<Incident> incidentList = incidents.findAll();
        long critical = threats.countBySeverity("CRITICAL");
        long high     = threats.countBySeverity("HIGH");
        long medium   = threats.countBySeverity("MEDIUM");
        long low      = threats.countBySeverity("LOW");
        int avgRisk   = threatList.isEmpty() ? 0 :
            (int) Math.round(threatList.stream().mapToInt(aran.model.Threat::getRiskScore).average().orElse(0));

        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(reportPath))) {
            w.println("╔══════════════════════════════════════════════════════════╗");
            w.println("║         ARAN SECURITY OPERATIONS REPORT                  ║");
            w.println("║   Autonomous Risk Analysis & Network Security Platform    ║");
            w.println("╚══════════════════════════════════════════════════════════╝");
            w.println();
            w.println("Generated  : " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            w.println("Report ID  : RPT-" + System.currentTimeMillis());
            w.println();
            w.println("═══════════════════════ EXECUTIVE SUMMARY ═══════════════");
            w.printf("  Total Events     : %d%n", events.count());
            w.printf("  Total Threats    : %d%n", threatList.size());
            w.printf("  Total Incidents  : %d%n", incidentList.size());
            w.printf("  Open Incidents   : %d%n", incidents.countOpen());
            w.printf("  Average Risk     : %d/100%n", avgRisk);
            w.printf("  Risk Level       : %s%n", RiskLevel.fromScore(avgRisk));
            w.println();
            w.println("═══════════════════════ THREAT BREAKDOWN ════════════════");
            w.printf("  CRITICAL : %d%n", critical);
            w.printf("  HIGH     : %d%n", high);
            w.printf("  MEDIUM   : %d%n", medium);
            w.printf("  LOW      : %d%n", low);
            w.println();

            w.println("═══════════════════════ THREAT FINDINGS ════════════════");
            if (threatList.isEmpty()) {
                w.println("  No threats detected.");
            } else {
                for (aran.model.Threat t : threatList) {
                    w.printf("  [%s] %-28s | Risk=%3d | %s%n",
                        pad(t.getSeverity(), 8), t.getType(), t.getRiskScore(), t.getExplanation());
                }
            }
            w.println();

            w.println("════════════════════════ INCIDENTS ════════════════════");
            if (incidentList.isEmpty()) {
                w.println("  No incidents recorded.");
            } else {
                for (Incident i : incidentList) {
                    w.printf("  %-16s | %-12s | Risk=%3d | %s%n",
                        i.getId(), i.getStatus(), i.getRiskScore(), i.getTitle());
                }
            }
            w.println();
            w.println("═══════════════════════ END OF REPORT ══════════════════");
        }

        audit.log("SYSTEM", "REPORT_GENERATED " + reportPath.getFileName());
        LOG.info("Report generated: " + reportPath);
        return reportPath;
    }

    private static String pad(String s, int width) {
        return String.format("%-" + width + "s", s == null ? "" : s);
    }
}
