package aran.storage;

import aran.model.Incident;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * In-memory + file-backed repository for Incident objects.
 * Thread-safe. Incidents are updated in-place (mutable status), so the
 * backing file is fully rewritten after every save/update — acceptable at
 * SOC-demo scale and far simpler than an append-and-compact log.
 */
public class IncidentRepository {
    private static final Logger LOG = Logger.getLogger(IncidentRepository.class.getName());

    private final List<Incident> incidents = new CopyOnWriteArrayList<>();
    private final Path file;

    public IncidentRepository() {
        this(Path.of("data/incidents.csv"));
    }

    public IncidentRepository(Path file) {
        this.file = file;
        load();
    }

    public synchronized void save(Incident i) {
        incidents.add(i);
        persistAll();
    }

    /** Call after mutating an incident's status to flush the change to disk. */
    public synchronized void update(Incident i) {
        persistAll();
    }

    public List<Incident> findAll() {
        return List.copyOf(incidents);
    }

    public Optional<Incident> findById(String id) {
        return incidents.stream()
            .filter(i -> id.equalsIgnoreCase(i.getId()))
            .findFirst();
    }

    public List<Incident> findByStatus(Incident.Status status) {
        return incidents.stream()
            .filter(i -> i.getStatus() == status)
            .collect(Collectors.toUnmodifiableList());
    }

    public List<Incident> findRecent(int count) {
        List<Incident> all = new ArrayList<>(incidents);
        all.sort(Comparator.comparing(Incident::getCreatedAt).reversed());
        return all.stream().limit(count).collect(Collectors.toUnmodifiableList());
    }

    public long countOpen() {
        return incidents.stream()
            .filter(i -> i.getStatus() != Incident.Status.RESOLVED)
            .count();
    }

    private synchronized void persistAll() {
        try {
            Files.createDirectories(file.getParent());
            StringBuilder sb = new StringBuilder();
            for (Incident i : incidents) sb.append(i.toCsv()).append(System.lineSeparator());
            Files.writeString(file, sb.toString(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        } catch (IOException ex) {
            LOG.warning("Could not persist incidents to " + file + ": " + ex.getMessage());
        }
    }

    private void load() {
        if (!Files.exists(file)) return;
        int loaded = 0, skipped = 0;
        try (BufferedReader r = Files.newBufferedReader(file)) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.isBlank()) continue;
                try {
                    incidents.add(Incident.fromCsv(line));
                    loaded++;
                } catch (Exception ex) {
                    LOG.warning("Skipping bad incident line: " + ex.getMessage());
                    skipped++;
                }
            }
        } catch (IOException ex) {
            LOG.warning("Could not load incidents from " + file + ": " + ex.getMessage());
        }
        if (loaded > 0 || skipped > 0)
            LOG.info("Loaded " + loaded + " incidents (" + skipped + " skipped) from " + file);
    }
}
