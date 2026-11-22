package dev.leakscan;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Collects raw plugin-channel payloads into a persistent (on disk, across sessions) per-server DB
 * and looks for patterns in them: fixed/variable format, counters, UUID-like fields, text fields
 * inside a binary packet. Not tied to any specific plugin's protocol — purely statistical byte
 * analysis, so the results are hints for manual verification, not facts.
 */
final class ChannelPatternAnalyzer {
    private static final int MIN_SAMPLES_FOR_ANALYSIS = 2;

    private ChannelPatternAnalyzer() {
    }

    static ChannelDb load(Path file) {
        Gson g = new Gson();
        try {
            if (Files.exists(file)) {
                try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    ChannelDb db = g.fromJson(r, ChannelDb.class);
                    if (db != null && db.channels != null) return db;
                }
            }
        } catch (Exception e) {
            LeakScanMod.LOGGER.warn("channel-db load failed for {}, starting fresh", file, e);
        }
        return new ChannelDb();
    }

    static synchronized void save(Path file, ChannelDb db) {
        Gson g = new GsonBuilder().setPrettyPrinting().create();
        try {
            Files.createDirectories(file.getParent());
            Files.write(file, g.toJson(db).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            LeakScanMod.LOGGER.error("channel-db save failed for {}", file, e);
        }
    }

    /** Netty thread: adds one captured channel packet to the DB (in memory; flushed to disk when the session closes). */
    static synchronized void record(ChannelDb db, String channel, byte[] data, int sampleBytes, int maxSamples) {
        ChannelDb.Entry e = db.channels.computeIfAbsent(channel, k -> new ChannelDb.Entry());
        long now = System.currentTimeMillis();
        if (e.totalPackets == 0) e.firstSeenMs = now;
        e.lastSeenMs = now;
        e.totalPackets++;

        String hex = ByteUtil.hex(data, Math.min(data.length, sampleBytes));
        Integer count = e.samples.get(hex);
        if (count != null) {
            e.samples.put(hex, count + 1);
        } else if (e.samples.size() < maxSamples) {
            e.samples.put(hex, 1);
        }
        // if there are already maxSamples unique samples and this is NOT a duplicate — just stop
        // storing raw bytes (totalPackets keeps counting) so the file doesn't grow forever.
    }

    /** Human-readable analysis of one channel's patterns. Empty if there is not enough data yet. */
    static List<String> analyze(ChannelDb.Entry e) {
        List<String> out = new ArrayList<>();
        if (e.samples.size() < MIN_SAMPLES_FOR_ANALYSIS) {
            // (there used to be a separate unreachable "samples.size()==1" branch under the < 2
            // guard — its wording was merged here)
            out.add(e.samples.isEmpty()
                ? "no channel packets captured yet"
                : "static payload: 1 unique sample out of " + e.totalPackets
                    + " packets — nothing changed, nothing to compare");
            return out;
        }

        List<byte[]> samples = new ArrayList<>();
        for (String hex : e.samples.keySet()) samples.add(decodeHex(hex));
        out.add("samples: " + samples.size() + " (out of " + e.totalPackets + " packets total)");

        // A special case that otherwise drowns in "variable length": the channel is just one whole
        // VarInt string (like minecraft:brand). Then N distinct DECODED strings — not a range of
        // byte lengths — is the meaningful answer (e.g. three different brands from three backends,
        // not "one variable-length string"). This used to be silently mixed into the generic
        // byte-level analysis.
        List<String> decoded = new ArrayList<>();
        boolean allDecode = true;
        for (byte[] b : samples) {
            String s = ByteUtil.tryReadFullVarString(b);
            if (s == null) {
                allDecode = false;
                break;
            }
            decoded.add(s);
        }
        if (allDecode) {
            Set<String> distinct = new LinkedHashSet<>(decoded);
            out.add("this is just a string (a VarInt length prefix + text), distinct values: " + distinct.size());
            for (String s : distinct) {
                out.add("value: \"" + s + "\"");
                quickScanInto(s, out);
            }
            return out;
        }

        int minLen = Integer.MAX_VALUE, maxLen = 0;
        for (byte[] b : samples) {
            minLen = Math.min(minLen, b.length);
            maxLen = Math.max(maxLen, b.length);
        }

        if (minLen == maxLen) {
            analyzeFixedLength(samples, minLen, out);
        } else {
            out.add("payload length varies: from " + minLen + " to " + maxLen + " bytes — likely a variable-length string/list");
            int prefix = commonPrefixLength(samples, minLen);
            if (prefix > 0) out.add("common prefix " + prefix + " bytes: " + ByteUtil.hex(samples.get(0), prefix));
            for (int i = 0; i < Math.min(samples.size(), 5); i++) {
                byte[] b = samples.get(i);
                if (b.length <= prefix) continue;
                String tail = ByteUtil.runs(java.util.Arrays.copyOfRange(b, prefix, b.length), 120);
                if (!tail.isEmpty()) {
                    out.add("after the prefix, sample " + (i + 1) + ": \"" + tail + "\"");
                    quickScanInto(tail, out);
                }
            }
        }
        return out;
    }

    private static void analyzeFixedLength(List<byte[]> samples, int len, List<String> out) {
        boolean[] constant = new boolean[len];
        for (int i = 0; i < len; i++) {
            byte v0 = samples.get(0)[i];
            boolean same = true;
            for (byte[] b : samples) if (b[i] != v0) { same = false; break; }
            constant[i] = same;
        }
        int fixedBytes = 0;
        for (boolean c : constant) if (c) fixedBytes++;
        out.add("fixed length " + len + " bytes, of which " + fixedBytes + " never change");

        int i = 0;
        while (i < len) {
            int start = i;
            boolean isConst = constant[i];
            while (i < len && constant[i] == isConst) i++;
            int runLen = i - start;
            if (isConst) describeConstantField(samples.get(0), start, runLen, out);
            else describeVariableField(samples, start, runLen, out);
        }
    }

    /** Constant (identical in all samples) bytes are usually not analyzed — but if there is readable
     * text inside, it is worth checking for leaks: it may be "interesting" precisely because it never
     * changes (a hardcoded host/path/token). The chunk may be "dirty" (separator bytes etc.), so we
     * extract printable substrings instead of requiring the whole range to be printable. */
    private static void describeConstantField(byte[] sample, int offset, int len, List<String> out) {
        if (len < 4) return;
        byte[] chunk = java.util.Arrays.copyOfRange(sample, offset, offset + len);
        String text = ByteUtil.runs(chunk, 200);
        if (text.isEmpty()) return;
        out.add("offset " + offset + ", " + len + " bytes (constant text, identical in all samples): \"" + text + "\"");
        quickScanInto(text, out);
    }

    private static void describeVariableField(List<byte[]> samples, int offset, int len, List<String> out) {
        // Text is checked FIRST: a short ASCII field (e.g. a 4-byte tag) would otherwise never reach
        // this check because the "looks like a number" branch below would take it.
        if (allPrintableAscii(samples, offset, len)) {
            List<String> texts = new ArrayList<>();
            for (byte[] b : samples) texts.add(new String(b, offset, len, java.nio.charset.StandardCharsets.US_ASCII).trim());
            out.add("offset " + offset + ", " + len + " bytes (text): " + joinCapped(texts, 6));
            for (String t : texts) quickScanInto(t, out);
            return;
        }
        if (len == 16) {
            List<String> uuids = new ArrayList<>();
            for (byte[] b : samples) uuids.add(bytesToUuid(b, offset));
            out.add("offset " + offset + ", 16 bytes — looks like a UUID, examples: " + joinCapped(uuids, 3));
            return;
        }
        if (len == 1 || len == 2 || len == 4 || len == 8) {
            List<Long> values = new ArrayList<>();
            for (byte[] b : samples) values.add(beLong(b, offset, len));
            boolean monotonic = true;
            for (int k = 1; k < values.size(); k++) if (values.get(k) < values.get(k - 1)) { monotonic = false; break; }
            // The length alone proves nothing: 4 bytes could equally be a counter, bit flags, a
            // float, a hash fragment or a random id. We confidently call it "a number" only when
            // the values grow monotonically (typical counter/tick behavior); otherwise we
            // explicitly say "may be".
            String kind = monotonic && !allEqual(values)
                ? "grows monotonically — looks like a counter/tick/sequence-id"
                : "changes inconsistently — may be a number, bit flags, a hash fragment or a random id, not necessarily a counter";
            out.add("offset " + offset + ", " + len + " bytes, " + kind + " (as a number: " + joinCapped(values, 8) + ")");
            return;
        }
        List<String> hexes = new ArrayList<>();
        for (byte[] b : samples) hexes.add(ByteUtil.hex(java.util.Arrays.copyOfRange(b, offset, offset + len), len));
        out.add("offset " + offset + ", " + len + " bytes (binary field), examples: " + joinCapped(hexes, 5));
    }

    private static void quickScanInto(String text, List<String> out) {
        for (String hit : Analyzer.quickScan(text)) out.add("⚠ looks like a leak right in the payload: " + hit);
    }

    private static boolean allEqual(List<Long> v) {
        for (Long x : v) if (!x.equals(v.get(0))) return false;
        return true;
    }

    private static boolean allPrintableAscii(List<byte[]> samples, int offset, int len) {
        for (byte[] b : samples) if (!isPrintableAscii(b, offset, len)) return false;
        return true;
    }

    private static boolean isPrintableAscii(byte[] b, int offset, int len) {
        for (int k = offset; k < offset + len; k++) {
            int c = b[k] & 0xFF;
            if (c != 0 && (c < 32 || c >= 127)) return false;
        }
        return true;
    }

    private static long beLong(byte[] b, int offset, int len) {
        long v = 0;
        for (int k = 0; k < len; k++) v = (v << 8) | (b[offset + k] & 0xFFL);
        return v;
    }

    private static String bytesToUuid(byte[] b, int offset) {
        long hi = beLong(b, offset, 8), lo = beLong(b, offset + 8, 8);
        return new java.util.UUID(hi, lo).toString();
    }

    private static int commonPrefixLength(List<byte[]> samples, int upTo) {
        int n = 0;
        outer:
        for (; n < upTo; n++) {
            byte v0 = samples.get(0)[n];
            for (byte[] b : samples) if (b[n] != v0) break outer;
        }
        return n;
    }

    private static String joinCapped(List<?> items, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(items.size(), max); i++) {
            if (i > 0) sb.append(", ");
            sb.append(items.get(i));
        }
        if (items.size() > max) sb.append(", ... ").append(items.size() - max).append(" more");
        return sb.toString();
    }

    private static byte[] decodeHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
