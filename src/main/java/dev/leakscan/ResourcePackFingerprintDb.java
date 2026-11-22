package dev.leakscan;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

/**
 * A GLOBAL (NOT per-host, unlike channel-db) DB: resource pack sha1 -> which hosts it was seen on.
 * If the same pack (byte-for-byte; a sha1 cannot be faked by accident) pops up under another
 * name/IP — that is a very strong signal of the same operator/network under another brand: a
 * network can change its name and IP without thinking, but almost nobody will redraw their custom
 * donation textures from scratch. <gameDir>/leakscan/resourcepack-fingerprints.json.
 */
final class ResourcePackFingerprintDb {
    LinkedHashMap<String, Entry> bySha1 = new LinkedHashMap<>();

    static final class Entry {
        long firstSeenMs;
        LinkedHashSet<String> hosts = new LinkedHashSet<>();
        String lastUrl;
    }

    ResourcePackFingerprintDb() {
    }

    static Path file() {
        return Config.dir().resolve("resourcepack-fingerprints.json");
    }

    static synchronized ResourcePackFingerprintDb load() {
        Gson g = new Gson();
        Path f = file();
        try {
            if (Files.exists(f)) {
                try (Reader r = Files.newBufferedReader(f, StandardCharsets.UTF_8)) {
                    ResourcePackFingerprintDb db = g.fromJson(r, ResourcePackFingerprintDb.class);
                    if (db != null && db.bySha1 != null) return db;
                }
            }
        } catch (Exception e) {
            LeakScanMod.LOGGER.warn("resourcepack-fingerprints.json load failed, starting fresh", e);
        }
        ResourcePackFingerprintDb db = new ResourcePackFingerprintDb();
        db.bySha1 = new LinkedHashMap<>();
        return db;
    }

    static synchronized void save(ResourcePackFingerprintDb db) {
        Gson g = new GsonBuilder().setPrettyPrinting().create();
        try {
            Files.createDirectories(file().getParent());
            Files.write(file(), g.toJson(db).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            LeakScanMod.LOGGER.error("resourcepack-fingerprints.json save failed", e);
        }
    }

    /**
     * Records (sha1, host, url) and returns the LIST OF OTHER HOSTS where this same sha1 was seen
     * before (empty if this is the first time, or it was previously seen only on THIS host).
     */
    synchronized LinkedHashSet<String> recordAndCheck(String sha1, String host, String url) {
        if (sha1 == null || sha1.isEmpty()) return new LinkedHashSet<>();
        Entry e = bySha1.get(sha1);
        LinkedHashSet<String> otherHosts = new LinkedHashSet<>();
        if (e == null) {
            e = new Entry();
            e.firstSeenMs = System.currentTimeMillis();
            bySha1.put(sha1, e);
        } else {
            for (String h : e.hosts) if (!h.equals(host)) otherHosts.add(h);
        }
        e.hosts.add(host);
        e.lastUrl = url;
        return otherHosts;
    }
}
