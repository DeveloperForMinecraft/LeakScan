package dev.leakscan;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * A global channel index ACROSS hosts: <gameDir>/leakscan/channel-db/_global.json,
 * channel -> which hosts it was seen on + total packets. The payload sample itself is taken from
 * the per-host DBs (channel-db/<host>.json); this is only the union: one rare channel on two
 * different hosts = almost certainly the same software/operator.
 */
final class GlobalChannelIndex {

    static class Entry {
        long totalPackets;
        LinkedHashSet<String> hosts = new LinkedHashSet<>();
    }

    private GlobalChannelIndex() {
    }

    static Path file() {
        return Config.dir().resolve("channel-db").resolve("_global.json");
    }

    static synchronized Map<String, Entry> load() {
        Gson g = new Gson();
        try {
            if (Files.exists(file())) {
                try (Reader r = Files.newBufferedReader(file(), StandardCharsets.UTF_8)) {
                    Type t = new TypeToken<LinkedHashMap<String, Entry>>() {
                    }.getType();
                    Map<String, Entry> m = g.fromJson(r, t);
                    if (m != null) return m;
                }
            }
        } catch (Exception e) {
            LeakScanMod.LOGGER.warn("global channel index load failed, starting fresh", e);
        }
        return new LinkedHashMap<>();
    }

    static synchronized void save(Map<String, Entry> db) {
        Gson g = new GsonBuilder().setPrettyPrinting().create();
        try {
            Files.createDirectories(file().getParent());
            Files.write(file(), g.toJson(db).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            LeakScanMod.LOGGER.error("global channel index save failed", e);
        }
    }

    /** Merges one session's channels (the host channel-db) into the global index. */
    static void mergeSession(ChannelDb hostDb, String hostKey) {
        if (hostDb == null || hostDb.channels == null || hostDb.channels.isEmpty()) return;
        Map<String, Entry> db = load();
        for (Map.Entry<String, ChannelDb.Entry> e : hostDb.channels.entrySet()) {
            Entry g = db.computeIfAbsent(e.getKey(), k -> new Entry());
            g.totalPackets += e.getValue().totalPackets;
            g.hosts.add(hostKey);
        }
        save(db);
    }

    /** Lines for the report section: channels seen on 2+ hosts, with a payload sample from the host DBs. */
    static List<String> describeMultiHostChannels(String selfHost) {
        Map<String, Entry> db = load();
        Map<String, Entry> multi = new TreeMap<>();
        for (Map.Entry<String, Entry> e : db.entrySet()) {
            if (e.getKey().startsWith("minecraft:")) continue; // brand and service channels exist on everyone — not a signal
            if (e.getValue().hosts.size() >= 2) multi.put(e.getKey(), e.getValue());
        }
        List<String> out = new ArrayList<>();
        if (multi.isEmpty()) return out;
        for (Map.Entry<String, Entry> e : multi.entrySet()) {
            Entry g = e.getValue();
            StringBuilder sb = new StringBuilder();
            sb.append('`').append(e.getKey()).append("` — ").append(g.totalPackets).append(" packets on ")
                .append(g.hosts.size()).append(" hosts: ").append(String.join(", ", g.hosts));
            String sample = firstSamplePayload(e.getKey(), g.hosts);
            if (sample != null && !sample.isEmpty()) sb.append(" | payload: \"").append(sample).append('\"');
            out.add(sb.toString());
        }
        return out;
    }

    /** The first decoded payload sample of a channel from any host DB (quoted in the report). */
    private static String firstSamplePayload(String channel, LinkedHashSet<String> hosts) {
        for (String host : hosts) {
            try {
                Path p = Config.dir().resolve("channel-db").resolve(host + ".json");
                if (!Files.exists(p)) continue;
                ChannelDb db = new Gson().fromJson(Files.newBufferedReader(p, StandardCharsets.UTF_8), ChannelDb.class);
                ChannelDb.Entry en = db == null ? null : db.channels.get(channel);
                if (en == null || en.samples.isEmpty()) continue;
                String hex = en.samples.keySet().iterator().next();
                byte[] bytes = new byte[hex.length() / 2];
                for (int i = 0; i < bytes.length; i++) {
                    bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
                }
                // 160, not 80: short JSON payloads (vv:server_details is 84 chars) were cut
                // mid-value and lost their meaning; long ones are still honestly shortened with "...".
                String s = ByteUtil.preview(bytes, 160);
                if (!s.isEmpty()) return ByteUtil.sanitizeInline(s);
            } catch (Exception ignored) {
            }
        }
        return null;
    }
}
