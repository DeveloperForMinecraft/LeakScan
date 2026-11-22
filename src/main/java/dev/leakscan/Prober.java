package dev.leakscan;

import net.minecraft.client.Minecraft;
import net.minecraft.client.network.play.ClientPlayNetHandler;
import net.minecraft.network.play.client.CTabCompletePacket;

import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Active probes. ONLY tab-complete (CTabCompletePacket): a read-only request that executes
 * nothing and does not change server state.
 * Responses with id >= BASE are intercepted by the sniffer and never reach the vanilla client.
 */
final class Prober {
    static final int BASE = 1_000_000;

    private static final class Pending {
        final String text;
        final long wallMs;
        final long nanoT0;
        final boolean retest; // a timing-candidate retest: does not consume the main budget

        Pending(String text, long wallMs, long nanoT0, boolean retest) {
            this.text = text;
            this.wallMs = wallMs;
            this.nanoT0 = nanoT0;
            this.retest = retest;
        }
    }

    private final Session s;
    private final ArrayDeque<String> queue = new ArrayDeque<>();
    private final Set<String> seen = new HashSet<>();
    /** How many retests of each probe are still in the queue (retest detection: seen is already taken by enqueue). */
    private final Map<String, Integer> retestRemaining = new ConcurrentHashMap<>();
    private final Map<Integer, Pending> pending = new ConcurrentHashMap<>();
    private int nextId = BASE;
    private int sent;
    private int budget;
    private long lastSendMs;
    /** Consecutive timeouts WITHOUT a single successful answer — a sign of a limbo/anti-bot screen
     * that doesn't answer tab-complete at all (see onLoggedIn: ~53/53 probes timed out in the real
     * Limbo/Auth test). */
    private int consecutiveTimeouts;
    private boolean paused;
    private long pausedSinceMs;
    /** How many times in a row we entered the pause without a single answer — the base for the exponential backoff. */
    private int pauseLevel;
    /** The wall-clock moment when the pause lifts itself: a pause = a temporary backoff, not an eternal state. */
    private long resumeAtMs;

    Prober(Session s) {
        this.s = s;
        this.budget = s.cfg.maxProbes;
    }

    synchronized boolean enqueue(String text) {
        if (!seen.add(text)) return false;
        queue.add(text);
        return true;
    }

    /** Manual probes raise the budget and lift the pause — if asked explicitly, the user wants to try. */
    synchronized boolean enqueueManual(String text) {
        boolean ok = enqueue(text);
        if (ok) {
            budget++;
            paused = false;
            consecutiveTimeouts = 0;
        }
        return ok;
    }

    /**
     * Timing-candidate retests: bypass the seen dedup and the main budget
     * (3 repeats per check — "if a candidate is discarded, the number of checks doesn't shrink").
     */
    synchronized void enqueueRetests(String text, int times) {
        retestRemaining.merge(text, times, Integer::sum);
        for (int i = 0; i < times; i++) queue.add(text);
    }

    synchronized int queued() {
        return queue.size();
    }

    int sent() {
        return sent;
    }

    boolean isPaused() {
        return paused;
    }

    synchronized void reset() {
        queue.clear();
        seen.clear();
        retestRemaining.clear();
        pending.clear();
        sent = 0;
        budget = s.cfg.maxProbes;
        consecutiveTimeouts = 0;
        paused = false;
        pauseLevel = 0;
        resumeAtMs = 0;
    }

    void onLogin() {
        if (!s.cfg.autoProbe || s.cfg.silentMode) return; // in silentMode probes are manual only: .ls probe defaults
        if (s.cfg.timingBaselineEnabled) enqueue(s.cfg.timingBaselineProbe + " ");
        if (!s.cfg.autoDefaultProbes) return;
        for (String p : Config.defaultProbes()) enqueue(p);
    }

    void onCommandTree(Set<String> namespaces, Set<String> roots) {
        if (!s.cfg.autoProbe || s.cfg.silentMode) return;
        if (s.cfg.autoNamespaceProbes) for (String ns : namespaces) enqueue("/" + ns + ":");
        if (s.cfg.autoRootArgProbes) for (String r : roots) if (!r.contains(":")) enqueue("/" + r + " ");
    }

    /** Main thread, once per tick. */
    void tick(long now) {
        ClientPlayNetHandler h = Minecraft.getInstance().getConnection();
        if (h == null) return;

        for (Iterator<Map.Entry<Integer, Pending>> it = pending.entrySet().iterator(); it.hasNext(); ) {
            Pending p = it.next().getValue();
            if (now - p.wallMs > s.cfg.probeTimeoutMs) {
                it.remove();
                s.analyzer.onProbeTimeout(p.text);
                onTimeoutForPauseTracking();
            }
        }

        // The pause is a TEMPORARY backoff, not an eternal state. The canary probe (a non-existent
        // command) did not work: some servers never answer tab-complete for
        // unknown commands, so lifting the pause by its answer was impossible. Now, when the
        // backoff expires, we simply continue the queue and reset the timeout counter (the next
        // pause requires another 8 in a row).
        if (paused && s.cfg.probePauseCanaryMs > 0 && now >= resumeAtMs) {
            paused = false;
            consecutiveTimeouts = 0;
            pauseLevel = Math.min(pauseLevel + 1, 3);
            s.reporter.probe(ByteUtil.kv("phase", s.analyzer.currentPhase, "event", "auto-probe-resumed",
                "note", "backoff expired — resuming the probe queue (an environment with a high " +
                    "tab-complete loss rate: backoff level " + pauseLevel + ", the next one is longer)"));
            s.notifyUser("\u00a77backoff expired — resuming probes (level " + pauseLevel + ")");
        }

        if (paused || sent >= budget || now - lastSendMs < s.cfg.probeIntervalMs) return;
        String text;
        boolean retest;
        synchronized (this) {
            text = queue.poll();
            // Retest status comes from the enqueueRetests counter: we used to check "is text in
            // seen", but enqueue() puts the text into seen at enqueue time — so ALL normal probes
            // were counted as repeats (the budget was never spent and Analyzer skipped their
            // parsing — a P0 caught in review).
            Integer rem = text == null ? null : retestRemaining.get(text);
            retest = rem != null && rem > 0;
            if (retest) {
                if (rem == 1) retestRemaining.remove(text);
                else retestRemaining.put(text, rem - 1);
            }
        }
        if (text == null) return;

        int id = nextId++;
        pending.put(id, new Pending(text, now, System.nanoTime(), retest));
        lastSendMs = now;
        if (!retest) sent++; // timing-candidate repeats do not consume the main budget
        h.send(new CTabCompletePacket(id, text));
    }

    private void onTimeoutForPauseTracking() {
        if (paused) return;
        consecutiveTimeouts++;
        if (consecutiveTimeouts >= s.cfg.pauseAfterConsecutiveTimeouts) {
            paused = true;
            pausedSinceMs = System.currentTimeMillis();
            // Exponential backoff: 30s -> 60s -> 120s -> 240s (cap). In a genuinely dead limbo
            // (never answers) this keeps budget usage at 8 probes per interval; on a rate-limited
            // server (drops part of tab-complete) the queue is guaranteed to continue instead of
            // stopping forever.
            long backoffMs = Math.min((long) s.cfg.probePauseCanaryMs << pauseLevel, 300_000L);
            resumeAtMs = pausedSinceMs + backoffMs;
            int phase = s.analyzer.currentPhase;
            s.analyzer.markProbingPaused(phase);
            s.reporter.probe(ByteUtil.kv("phase", phase, "event", "auto-probe-paused",
                "consecutiveTimeouts", consecutiveTimeouts,
                "resumeInMs", backoffMs,
                "note", "a run of consecutive timeouts: either a limbo/anti-bot, or the server drops " +
                    "part of tab-complete (rate limit). Will resume on my own in " + (backoffMs / 1000) + " s"));
            s.notifyUser("\u00a77auto-probes: paused for " + (backoffMs / 1000) + " s (" + consecutiveTimeouts
                + " timeouts in a row; the environment either stays silent or drops part of the requests) — will resume on my own.");
        }
    }

    /** Netty thread. */
    void onResponse(int id, List<String> texts, List<String> tips) {
        Pending p = pending.remove(id);
        if (p == null) return;
        consecutiveTimeouts = 0; // at least one answer arrived - the environment is alive
        pauseLevel = 0; // and its losses look random — the next backoff is minimal again
        long rttMs = (System.nanoTime() - p.nanoT0) / 1_000_000L;
        final boolean retest = p.retest;
        Minecraft.getInstance().execute(() -> s.analyzer.onProbeResult(p.text, texts, tips, rttMs, retest));
    }
}
