package dev.leakscan;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

/** JSONL logs (packets/probes) + the final report.md and findings.json. */
final class Reporter {
    private final Path dir;
    private BufferedWriter packets, probes;
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final Gson pretty = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();

    Reporter(Path dir) {
        this.dir = dir;
        try {
            Files.createDirectories(dir);
            packets = Files.newBufferedWriter(dir.resolve("packets.jsonl"), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            probes = Files.newBufferedWriter(dir.resolve("probes.jsonl"), StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            LeakScanMod.LOGGER.error("cannot open log files in {}", dir, e);
        }
    }

    Path dir() {
        return dir;
    }

    /**
     * The full (untruncated) list for probes/findings with more items than is reasonable to carry
     * in the main log/finding — probes.jsonl cuts suggestions at 300 and a finding's evidence at
     * 200, and the full list used to be lost entirely (existing NOWHERE, including findings.json).
     * Returns a path relative to the session directory — for referencing from the report/finding.
     */
    synchronized String saveFullList(String label, List<String> items) {
        try {
            Path fullDir = dir.resolve("full-lists");
            Files.createDirectories(fullDir);
            String safe = label.trim().replaceAll("[^A-Za-z0-9._-]+", "_");
            if (safe.isEmpty()) safe = "probe";
            if (safe.length() > 60) safe = safe.substring(0, 60);
            Path f = fullDir.resolve(safe + ".txt");
            int n = 1;
            while (Files.exists(f)) { // different probes may collide after name sanitization
                f = fullDir.resolve(safe + "_" + (++n) + ".txt");
            }
            Files.write(f, String.join("\n", items).getBytes(StandardCharsets.UTF_8));
            return "full-lists/" + f.getFileName();
        } catch (IOException e) {
            LeakScanMod.LOGGER.error("cannot save full list for {}", label, e);
            return null;
        }
    }

    synchronized void packet(String type, Map<String, Object> data) {
        write(packets, type, data);
    }

    synchronized void probe(Map<String, Object> data) {
        write(probes, "PROBE", data);
    }

    private void write(BufferedWriter w, String type, Map<String, Object> data) {
        if (w == null) return;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("t", System.currentTimeMillis());
        m.put("type", type);
        m.putAll(data);
        try {
            w.write(gson.toJson(m));
            w.newLine();
            w.flush();
        } catch (IOException ignored) {
        }
    }

    synchronized void close() {
        try {
            if (packets != null) packets.close();
            if (probes != null) probes.close();
        } catch (IOException ignored) {
        }
        packets = null;
        probes = null;
    }

    synchronized void writeReport(Session s) {
        Analyzer a = s.analyzer;
        List<Finding> findings = a.snapshot(); // already sorted: by phase first, by severity within
        List<Analyzer.ProbeStat> allStats = a.probeStats();
        StringBuilder sb = new StringBuilder();
        String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

        sb.append("# LeakScan report\n\n");
        sb.append("- Server: `").append(dir.getFileName()).append("`\n");
        sb.append("- Permission profile: **").append(s.cfg.label).append("**\n");
        sb.append("- Generated: ").append(now).append(", duration ").append((System.currentTimeMillis() - s.startMs) / 1000).append(" s\n");
        sb.append("- Environments/servers detected during the session: **").append(a.phases.size())
            .append("** (from login-phase packets, see PhaseDetector); the LOCAL client-side LoggedInEvent from Forge "
                + "fired ").append(s.loginCount).append(" time(s) — a client event, not a server one, here only for cross-checking\n\n");

        int[] bySev = new int[Severity.values().length];
        for (Finding f : findings) bySev[f.severity.ordinal()]++;
        sb.append("## Summary (whole session)\n\n");
        for (int i = Severity.values().length - 1; i >= 0; i--) sb.append("- ").append(Severity.values()[i]).append(": ").append(bySev[i]).append('\n');

        sb.append("\n## Coverage\n\n");
        sb.append("- JoinGame packet captured at least once: ").append(s.sawJoin ? "yes" : "no (worlds taken from client state, if possible)").append('\n');
        sb.append("- Command tree packet captured at least once: ").append(s.sawCommandList ? "yes" : "no (tree taken from client state)").append('\n');
        sb.append("- Probes sent in total: ").append(s.prober.sent()).append(", queued: ").append(s.prober.queued()).append('\n');

        // Findings and probes — per phase
        Map<Integer, List<Finding>> findingsByPhase = new LinkedHashMap<>();
        for (Finding f : findings) findingsByPhase.computeIfAbsent(f.phase, k -> new ArrayList<>()).add(f);
        Map<Integer, List<Analyzer.ProbeStat>> statsByPhase = new LinkedHashMap<>();
        for (Analyzer.ProbeStat p : allStats) statsByPhase.computeIfAbsent(p.phase, k -> new ArrayList<>()).add(p);

        TreeSet<String> allChannels = new TreeSet<>();
        Map<Integer, Long> medianRttByPhase = new LinkedHashMap<>();
        for (PhaseInfo ph : a.phases) {
            List<Finding> fs = findingsByPhase.get(ph.index);
            sb.append("\n---\n\n## Server/phase ").append(ph.index);
            long offsetS = (ph.startMs - s.startMs) / 1000;
            sb.append(" (t+").append(offsetS).append("s)\n\n");
            if (ph.index == 0) {
                sb.append("The initial session entry.\n\n");
            } else {
                sb.append("Reason for splitting: the packets ").append(String.join(", ", ph.triggers))
                    .append(" arrived in a row — looks like a backend switch behind a proxy (or a full client re-initialization).\n\n");
            }
            boolean stub = "?".equals(ph.brand) && ph.channels.isEmpty() && ph.rootCommands.isEmpty() && (fs == null || fs.isEmpty());
            if (stub) {
                sb.append("⚠ This looks like an empty shell without real content — no brand, no channels, no commands, "
                    + "no findings. Most likely a pre-login/limbo splash screen (e.g. a bot-check screen) or a moment "
                    + "before the sniffer was fully installed, not a separate server of its own.\n\n");
            }
            sb.append("- Brand: `").append(ph.brand).append("`\n");
            sb.append("- Worlds: ").append(ph.worlds.isEmpty() ? "unknown" : String.join(", ", ph.worlds)).append("\n");
            if (ph.joinInts != null && !ph.joinInts.isEmpty()) {
                sb.append("- JoinGame ints (entityId, ...): ").append(ph.joinInts).append("\n");
            }
            sb.append("- Commands in the tree: ").append(ph.rootCommands.size()).append("\n");
            if (!ph.sawJoin) {
                sb.append("- ⚠ JoinGame for this phase was not captured directly (maybe the server didn't manage to send it "
                    + "before the session ended, or the sniffer installed later) — worlds/entityId may be missing from the report.\n");
            }
            if (!ph.sawCommandList) {
                sb.append("- ⚠ The command tree for this phase was not captured — its \"commands outside the tree\" check is unreliable.\n");
            }
            if (ph.autoProbingPaused) {
                sb.append("- ⚠ This phase's auto-probes were suspended after a run of consecutive timeouts — the environment "
                    + "apparently doesn't answer tab-complete at all (typical of pre-login/limbo/anti-bot screens). Probe budget was not wasted.\n");
            }
            if (!ph.channels.isEmpty()) {
                sb.append("- Channels of this phase: ").append(String.join(", ", ph.channels)).append("\n");
                allChannels.addAll(ph.channels);
            }

            sb.append("\n### Findings\n");
            if (fs == null || fs.isEmpty()) {
                sb.append("\nNothing found.\n");
            } else {
                for (Finding f : fs) {
                    sb.append("\n#### [").append(f.severity).append("] ").append(f.title).append("\n\n");
                    sb.append("Category: `").append(f.category).append("`, hits: ").append(f.hits).append("\n\n");
                    sb.append("What to do: ").append(f.recommendation).append("\n\n");
                    int n = 0;
                    for (String e : f.evidence) {
                        if (n++ >= 40) {
                            sb.append("- ... ").append(f.evidence.size() - 40).append(" more (see findings.json)\n");
                            break;
                        }
                        sb.append("- `").append(e.replace("`", "'")).append("`\n");
                    }
                }
            }

            List<Analyzer.ProbeStat> stats = statsByPhase.get(ph.index);
            if (stats != null && !stats.isEmpty()) {
                sb.append("\n### Probes (tab-complete) of this phase\n\n| probe | answers | RTT ms |\n|---|---|---|\n");
                List<Long> rtts = new ArrayList<>();
                int timeouts = 0;
                for (Analyzer.ProbeStat p : stats) {
                    sb.append("| `").append(p.probe.replace("|", "\\|")).append(p.retest ? " (repeat)" : "").append("` | ")
                        .append(p.timeout ? "no answer" : String.valueOf(p.count))
                        .append(" | ").append(p.timeout ? "-" : String.valueOf(p.rttMs)).append(" |\n");
                    if (p.timeout) timeouts++;
                    else if (!p.retest) rtts.add(p.rttMs); // candidate repeats don't enter the median
                }
                if (!rtts.isEmpty()) {
                    List<Long> sorted = new ArrayList<>(rtts);
                    Collections.sort(sorted);
                    long median = sorted.get(sorted.size() / 2);
                    medianRttByPhase.put(ph.index, median);
                    sb.append("\nMedian RTT: ").append(median).append(" ms. Unanswered probes: ").append(timeouts).append(".\n");
                    if (!ph.baselineRtts.isEmpty()) {
                        List<Long> b = new ArrayList<>(ph.baselineRtts);
                        Collections.sort(b);
                        long baseMedian = b.get(b.size() / 2);
                        sb.append("Reference — the RTT of a deliberately non-existent command (`").append(s.cfg.timingBaselineProbe)
                            .append("`) in the same session: ").append(baseMedian).append(" ms (").append(b.size()).append(" measurement(s)).\n");
                    }
                    boolean any = false;
                    StringBuilder anomalies = new StringBuilder();
                    for (Analyzer.ProbeStat p : stats) {
                        if (p.retest || p.timeout) continue;
                        if (p.rttMs > Math.max(3 * median, median + 40)) {
                            // candidates refuted by automatic repeats (x3) are removed from the report
                            if (a.isTimingRejected(ph.index, p.probe)) continue;
                            anomalies.append("- `").append(p.probe).append("` — ").append(p.rttMs)
                                .append(" ms, answers: ").append(p.count);
                            if (a.isTimingConfirmed(ph.index, p.probe)) anomalies.append(" — **confirmed by 3 repeats**");
                            else anomalies.append(" — automatically repeated for verification");
                            anomalies.append('\n');
                            any = true;
                        }
                    }
                    if (any) {
                        sb.append("Timing-channel candidates (RTT > max(3×median, median+40 ms)):\n\n").append(anomalies)
                            .append("\nThese are SINGLE outliers (each probe was sent only once) — based on a single measurement "
                                + "this may be ordinary lag/chunk loading, not a real timing channel. Before drawing conclusions, "
                                + "repeat these specific probes manually several times (`.ls probe /name~`) and compare the spread.\n");
                    } else {
                        sb.append("Timing-channel candidates (RTT > max(3×median, median+40 ms)): none.\n");
                    }
                }
            }

            if (ph.headerFooterCount >= 3 && ph.headerFooterFirstMs != null && !ph.headerFooterLastMs.equals(ph.headerFooterFirstMs)) {
                double sec = (ph.headerFooterLastMs - ph.headerFooterFirstMs) / 1000.0;
                sb.append("\n### Tab header/footer update rate\n\n");
                sb.append("- ").append(ph.headerFooterCount).append(" packets over ").append(String.format("%.1f", sec))
                    .append(" s (").append(String.format("%.2f", ph.headerFooterCount / sec)).append(" p/s) — by itself "
                        + "it doesn't identify a plugin, but a stable rate is another fingerprint for comparing servers.\n");
            }
            if (ph.scoreUpdateCount >= 5 && ph.scoreUpdateFirstMs != null && !ph.scoreUpdateLastMs.equals(ph.scoreUpdateFirstMs)) {
                double sec = (ph.scoreUpdateLastMs - ph.scoreUpdateFirstMs) / 1000.0;
                sb.append("\n### Scoreboard score update rate\n\n");
                sb.append("- ").append(ph.scoreUpdateCount).append(" packets over ").append(String.format("%.1f", sec))
                    .append(" s (").append(String.format("%.2f", ph.scoreUpdateCount / sec)).append(" p/s) — a high and "
                        + "stable rate is typical of animated scoreboards (FeatherBoard and the like).\n");
            }

            if (!ph.tpsSamples.isEmpty()) {
                List<Double> t = ph.tpsSamples;
                double sum = 0, min = 20.5, max = 0;
                for (double x : t) {
                    sum += x;
                    min = Math.min(min, x);
                    max = Math.max(max, x);
                }
                double mean = sum / t.size();
                sb.append("\n### TPS (estimated from world age increments in TimeUpdate)\n\n");
                sb.append("- measurements: ").append(t.size()).append(", mean: ").append(String.format("%.1f", mean))
                    .append(", min/max: ").append(String.format("%.1f", min)).append("/").append(String.format("%.1f", max)).append('\n');
                if (mean < 19.0) {
                    sb.append("- noticeably below 20 — the server in this phase was probably lagging (or its tick rate is set so).\n");
                }
            }

            if (ph.keepAliveIntervalsMs.size() >= 3) {
                sb.append("\n### KeepAlive: packet intervals (passive, no probes)\n\n");
                List<Long> iv = ph.keepAliveIntervalsMs;
                double mean = 0;
                for (long x : iv) mean += x;
                mean /= iv.size();
                double variance = 0;
                for (long x : iv) variance += (x - mean) * (x - mean);
                double stddev = Math.sqrt(variance / iv.size());
                long min = Collections.min(iv), max = Collections.max(iv);
                int near50 = 0;
                for (long x : iv) if (Math.abs(x % 50) <= 3 || Math.abs(x % 50 - 50) <= 3) near50++;
                sb.append("- packets: ").append(ph.keepAliveCount).append(", intervals: ").append(iv.size()).append('\n');
                sb.append("- mean: ").append(String.format("%.0f", mean)).append(" ms, stddev: ")
                    .append(String.format("%.1f", stddev)).append(" ms, min/max: ").append(min).append("/").append(max).append(" ms\n");
                sb.append("- close to a multiple of 50 ms (±3 ms): ").append(near50).append(" of ").append(iv.size()).append('\n');
                sb.append("Raw statistics without a ready-made conclusion: interpretation is ambiguous (network jitter, "
                    + "TPS load etc. also matter). A low stddev with intervals NOT multiples of 50 ms is a weak hint of "
                    + "async network handling, but it is not proof of a specific core.\n");
            }
        }

        if (medianRttByPhase.size() >= 2) {
            List<Integer> ordered = new ArrayList<>(medianRttByPhase.keySet());
            Collections.sort(ordered);
            StringBuilder rttNotes = new StringBuilder();
            for (int i = 1; i < ordered.size(); i++) {
                long prev = medianRttByPhase.get(ordered.get(i - 1));
                long cur = medianRttByPhase.get(ordered.get(i));
                if (prev <= 0) continue;
                double ratio = (double) cur / prev;
                if (ratio >= 1.5 || ratio <= 1 / 1.5) {
                    rttNotes.append("- phase ").append(ordered.get(i - 1)).append(" (").append(prev)
                        .append(" ms) → phase ").append(ordered.get(i)).append(" (").append(cur)
                        .append(" ms): ").append(String.format("%.1f", Math.max(ratio, 1 / ratio)))
                        .append("× ").append(ratio > 1 ? "higher" : "lower")
                        .append(" — looks like a different network hop (another backend/further away), not just measurement noise\n");
                }
            }
            if (rttNotes.length() > 0) {
                sb.append("\n---\n\n## Latency (RTT) between phases\n\n").append(rttNotes);
            }
        }

        sb.append("\n---\n\n## Channels (merged over the whole session)\n\n");
        for (String c : allChannels) sb.append("- `").append(c).append("`\n");

        if (s.cfg.globalChannelIndex) {
            List<String> multi = GlobalChannelIndex.describeMultiHostChannels(s.hostKey);
            if (!multi.isEmpty()) {
                sb.append("\n## Channels seen on multiple hosts (global DB)\n\n");
                sb.append("One channel on two different hosts — almost certainly the same software/operator. Payload samples come from the corresponding host DBs.\n\n");
                for (String line : multi) sb.append("- ").append(line).append('\n');
            }
        }

        if (s.channelDb != null && !s.channelDb.channels.isEmpty()) {
            sb.append("\n## Channel payload patterns (a per-server DB, accumulated across sessions)\n\n");
            sb.append("The analysis is heuristic (byte comparison between samples); these are hints for manual verification, not a ready diagnosis.\n");
            for (Map.Entry<String, ChannelDb.Entry> e : s.channelDb.channels.entrySet()) {
                sb.append("\n### `").append(e.getKey()).append("`\n\n");
                for (String line : ChannelPatternAnalyzer.analyze(e.getValue())) sb.append("- ").append(line).append('\n');
            }
        }

        sb.append("\n## Packet histogram (the whole session, including filtered noise)\n\n");
        List<Map.Entry<String, AtomicInteger>> hist = new ArrayList<>(s.histogram.entrySet());
        Collections.sort(hist, (x, y) -> y.getValue().get() - x.getValue().get());
        int shown = 0;
        for (Map.Entry<String, AtomicInteger> e : hist) {
            if (shown++ >= 60) break;
            sb.append("- ").append(e.getKey()).append(": ").append(e.getValue().get()).append('\n');
        }

        try {
            Files.createDirectories(dir);
            Files.write(dir.resolve("report-full.md"), sb.toString().getBytes(StandardCharsets.UTF_8));
            if (s.cfg.compactReport) {
                Files.write(dir.resolve("report.md"),
                    buildCompact(s, a, findings).toString().getBytes(StandardCharsets.UTF_8));
            } else {
                Files.write(dir.resolve("report.md"), sb.toString().getBytes(StandardCharsets.UTF_8));
            }
            Files.write(dir.resolve("findings.json"), pretty.toJson(findings).getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            LeakScanMod.LOGGER.error("cannot write report", e);
        }
    }

    /**
     * A compact digest: TL;DR at the top, one line per finding, only confirmed timing anomalies,
     * phase metrics on one line. Nothing is lost — the full format remains in report-full.md and
     * findings.json.
     */
    private StringBuilder buildCompact(Session s, Analyzer a, List<Finding> findings) {
        StringBuilder c = new StringBuilder();
        String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        c.append("# LeakScan — brief report\n\n");
        c.append("- Server: `").append(dir.getFileName()).append("`, profile: **").append(s.cfg.label)
            .append("**, ").append(now).append(", duration ")
            .append((System.currentTimeMillis() - s.startMs) / 1000).append(" s, phases: ").append(a.phases.size()).append('\n');
        if (s.pingVersionName != null) {
            c.append("- Pre-login ping: version=`").append(s.pingVersionName).append('`');
            if (s.pingFaviconSha1 != null) c.append(", favicon sha1=`").append(s.pingFaviconSha1, 0, 12).append("...`");
            if (!s.pingSampleNames.isEmpty()) c.append(", names in the sample: ").append(s.pingSampleNames.size());
            c.append('\n');
        }

        int[] bySev = new int[Severity.values().length];
        for (Finding f : findings) bySev[f.severity.ordinal()]++;
        StringBuilder sevLine = new StringBuilder();
        for (int i = Severity.values().length - 1; i >= 1; i--) {
            if (bySev[i] > 0) sevLine.append(Severity.values()[i]).append(": ").append(bySev[i]).append("  ");
        }
        c.append("- Findings: ").append(sevLine.length() > 0 ? sevLine.toString().trim() : "none").append('\n');

        List<Finding> top = new ArrayList<>(findings);
        top.sort((x, y) -> {
            int d = y.severity.ordinal() - x.severity.ordinal();
            return d != 0 ? d : y.hits - x.hits;
        });
        if (!top.isEmpty()) {
            c.append("\n## TL;DR — the essentials\n\n");
            // Same-type findings (the brand of each phase etc.) are merged: otherwise the top-10
            // fills with five lines of "The server brand reveals software: ..." with different
            // values of the same thing.
            java.util.Map<String, List<Finding>> groups = new java.util.LinkedHashMap<>();
            for (Finding f : top) {
                if (f.severity == Severity.INFO) continue;
                String prefix = f.title.length() > 28 ? f.title.substring(0, 28) : f.title;
                groups.computeIfAbsent(prefix, k -> new ArrayList<>()).add(f);
            }
            int n = 0;
            for (Map.Entry<String, List<Finding>> gr : groups.entrySet()) {
                if (n++ >= 10) break;
                List<Finding> g = gr.getValue();
                Finding f0 = g.get(0);
                c.append(n).append(". **[").append(f0.severity).append("] ");
                if (g.size() > 1) {
                    // the prefix comes from the group key: it is guaranteed not longer than the title
                    // (a substring would throw)
                    c.append(gr.getKey()).append("...** ×").append(g.size())
                        .append(" variants (phases ").append(joinPhases(g)).append(")");
                } else {
                    c.append(f0.title).append("** (phase ").append(f0.phase).append(", ×").append(f0.hits).append(")");
                }
                String ev1 = f0.evidence.isEmpty() ? "" : " — " + shorten(f0.evidence.iterator().next(), 80);
                c.append(ev1).append('\n');
            }
        }

        Map<Integer, List<Finding>> byPhase = new LinkedHashMap<>();
        for (Finding f : findings) byPhase.computeIfAbsent(f.phase, k -> new ArrayList<>()).add(f);
        Map<Integer, List<Analyzer.ProbeStat>> statsByPhase = new LinkedHashMap<>();
        for (Analyzer.ProbeStat p : a.probeStats()) statsByPhase.computeIfAbsent(p.phase, k -> new ArrayList<>()).add(p);

        for (PhaseInfo ph : a.phases) {
            c.append("\n## Phase ").append(ph.index).append(" (t+").append((ph.startMs - s.startMs) / 1000).append("s)\n\n");
            StringBuilder meta = new StringBuilder();
            meta.append("brand=").append(ph.brand);
            if (!ph.worlds.isEmpty()) meta.append("; worlds: ").append(String.join(", ", ph.worlds));
            meta.append("; commands in tree: ").append(ph.rootCommands.size());
            if (!ph.channels.isEmpty()) meta.append("; channels: ").append(ph.channels.size());
            if (!ph.serverMods.isEmpty()) meta.append("; mods (fml/ping): ").append(String.join(", ", ph.serverMods));
            c.append(meta).append('\n');
            if (ph.autoProbingPaused) c.append("⚠ auto-probes were suspended (a run of timeouts; the backoff resumes on its own)\n");
            List<Finding> fs = byPhase.get(ph.index);
            if (fs == null || fs.isEmpty()) {
                c.append("No findings.\n");
            } else {
                for (Finding f : fs) {
                    c.append("- [").append(f.severity).append("] ").append(f.title);
                    if (f.hits > 1) c.append(" ×").append(f.hits);
                    int shown = 0;
                    for (String e : f.evidence) {
                        if (shown++ >= 2) break;
                        c.append("\n    - ").append(shorten(e, 100));
                    }
                    if (f.evidence.size() > 2) c.append("\n    - ... ").append(f.evidence.size() - 2).append(" more in report-full.md");
                    c.append('\n');
                }
            }
            List<Analyzer.ProbeStat> stats = statsByPhase.get(ph.index);
            if (stats != null && !stats.isEmpty()) {
                List<Long> rtts = new ArrayList<>();
                int timeouts = 0;
                for (Analyzer.ProbeStat p : stats) {
                    if (p.timeout) timeouts++;
                    else if (!p.retest) rtts.add(p.rttMs);
                }
                if (!rtts.isEmpty()) {
                    Collections.sort(rtts);
                    c.append("\nProbes: ").append(stats.size()).append(", unanswered: ").append(timeouts)
                        .append(", median RTT: ").append(rtts.get(rtts.size() / 2)).append(" ms");
                    c.append(". Timing: ");
                    boolean anyTim = false;
                    for (Analyzer.ProbeStat p : stats) {
                        if (a.isTimingConfirmed(ph.index, p.probe)) {
                            c.append("`").append(p.probe.trim()).append("` confirmed by repeats; ");
                            anyTim = true;
                        }
                    }
                    if (!anyTim) c.append("none confirmed (candidates were discarded by the x3 checks, or there were no outliers)");
                    c.append('\n');
                }
            }
            if (!ph.tpsSamples.isEmpty()) {
                double sum = 0;
                for (double x : ph.tpsSamples) sum += x;
                c.append("TPS ~").append(String.format("%.1f", sum / ph.tpsSamples.size()))
                    .append(" (").append(ph.tpsSamples.size()).append(" measurements)\n");
            }
        }
        c.append("\nFull details: `report-full.md`, `findings.json`, `packets.jsonl`, `probes.jsonl`, `full-lists/`.\n");
        return c;
    }

    private static String joinPhases(List<Finding> g) {
        TreeSet<Integer> ph = new TreeSet<>();
        for (Finding f : g) ph.add(f.phase);
        StringBuilder sb = new StringBuilder();
        for (int p : ph) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(p);
        }
        return sb.toString();
    }

    private static String shorten(String s, int max) {
        if (s == null) return "";
        String t = s.replace('\n', ' ');
        return t.length() > max ? t.substring(0, max) + "..." : t;
    }
}
