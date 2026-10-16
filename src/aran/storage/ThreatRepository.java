package aran.storage;

import aran.model.Threat;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * In-memory + file-backed repository for Threat objects.
 * Thread-safe via CopyOnWriteArrayList. Threats are immutable once created,
 * so persistence is a simple append to data/threats.csv.
 */
public class ThreatRepository {
    private static final Logger LOG = Logger.getLogger(ThreatRepository.class.getName());

    private final List<Threat> threats = new CopyOnWriteArrayList<>();
    private final Path file;

    public ThreatRepository() {
        this(Path.of("data/threats.csv"));
    }

    public ThreatRepository(Path file) {
        this.file = file;
        load();
    }

    public synchronized void save(Threat t) {
        threats.add(t);
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, t.toCsv() + System.lineSeparator(),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) {
            LOG.warning("Could not persist threat " + t.getId() + ": " + ex.getMessage());
        }
    }

    public List<Threat> findAll() {
        return List.copyOf(threats);
    }

    public Optional<Threat> findById(String id) {
        return threats.stream().filter(t -> id.equals(t.getId())).findFirst();
    }

    public List<Threat> findRecent(int count) {
        List<Threat> all = new ArrayList<>(threats);
        all.sort(Comparator.comparing(Threat::getDetectedAt).reversed());
        return all.stream().limit(count).collect(Collectors.toUnmodifiableList());
    }

    public long count() { return threats.size(); }

    public long countBySeverity(String severity) {
        return threats.stream()
            .filter(t -> severity.equalsIgnoreCase(t.getSeverity()))
            .count();
    }

    private void load() {
        if (!Files.exists(file)) return;
        int loaded = 0, skipped = 0;
        try (BufferedReader r = Files.newBufferedReader(file)) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.isBlank()) continue;
                try {
                    threats.add(Threat.fromCsv(line));
                    loaded++;
                } catch (Exception ex) {
                    LOG.warning("Skipping bad threat line: " + ex.getMessage());
                    skipped++;
                }
            }
        } catch (IOException ex) {
            LOG.warning("Could not load threats from " + file + ": " + ex.getMessage());
        }
        if (loaded > 0 || skipped > 0)
            LOG.info("Loaded " + loaded + " threats (" + skipped + " skipped) from " + file);
    }
}
