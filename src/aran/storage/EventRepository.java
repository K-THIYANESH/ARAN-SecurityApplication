package aran.storage;

import aran.model.SecurityEvent;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * In-memory + file-backed repository for SecurityEvent objects.
 * Thread-safe. Survives application restarts by persisting to CSV.
 */
public class EventRepository {
    private static final Logger LOG = Logger.getLogger(EventRepository.class.getName());

    private final List<SecurityEvent> events = new CopyOnWriteArrayList<>();
    private final Path file;

    public EventRepository() {
        this(Path.of("data/events.csv"));
    }

    public EventRepository(Path file) {
        this.file = file;
        load();
    }

    public synchronized void save(SecurityEvent e) {
        events.add(e);
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, e.toCsv() + System.lineSeparator(),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) {
            LOG.warning("Could not persist event " + e.getId() + ": " + ex.getMessage());
        }
    }

    public List<SecurityEvent> findAll() {
        return List.copyOf(events);
    }

    public List<SecurityEvent> findByUsername(String username) {
        return events.stream()
            .filter(e -> username.equalsIgnoreCase(e.getUsername()))
            .collect(Collectors.toUnmodifiableList());
    }

    public List<SecurityEvent> findRecent(int count) {
        List<SecurityEvent> all = new ArrayList<>(events);
        all.sort(Comparator.comparing(SecurityEvent::getTimestamp).reversed());
        return all.stream().limit(count).collect(Collectors.toUnmodifiableList());
    }

    public long count() { return events.size(); }

    public boolean existsById(String id) {
        return events.stream().anyMatch(e -> id.equals(e.getId()));
    }

    private void load() {
        if (!Files.exists(file)) return;
        int loaded = 0, skipped = 0;
        try (BufferedReader r = Files.newBufferedReader(file)) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.isBlank()) continue;
                try {
                    SecurityEvent e = SecurityEvent.fromCsv(line);
                    events.add(e);
                    loaded++;
                } catch (Exception ex) {
                    LOG.warning("Skipping bad event line: " + ex.getMessage());
                    skipped++;
                }
            }
        } catch (IOException ex) {
            LOG.warning("Could not load events from " + file + ": " + ex.getMessage());
        }
        if (loaded > 0 || skipped > 0)
            LOG.info("Loaded " + loaded + " events (" + skipped + " skipped) from " + file);
    }
}
