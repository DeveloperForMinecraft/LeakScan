package dev.leakscan;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.TreeSet;

/** Metadata of one "environment" within a session (see PhaseDetector). For reporting only. */
final class PhaseInfo {
    final int index;
    final long startMs;
    final List<String> triggers; // which packets caused the transition into this phase (empty for phase 0)
    final TreeSet<String> rootCommands = new TreeSet<>();
    final TreeSet<String> channels = new TreeSet<>();
    /** Channel -> the first decoded payload content (quoted in the "Channels seen" finding). */
    final java.util.LinkedHashMap<String, String> channelSamples = new java.util.LinkedHashMap<>();
    final TreeSet<String> customSounds = new TreeSet<>();
    final TreeSet<String> serverMods = new TreeSet<>(); // mods from fml:handshake (login phase, Forge)
    /** uuid -> how many times UPDATE_LATENCY arrived (for finding hidden players with a live ping). */
    final java.util.Map<java.util.UUID, Long> latencyCount = new java.util.HashMap<>();
    /** uuid -> when removed from the tab list (REMOVE); ping in the first seconds after REMOVE is a re-sync, not vanish. */
    final java.util.Map<java.util.UUID, Long> playerInfoRemovedAt = new java.util.HashMap<>();
    /** uuid -> how many latency updates arrived MORE THAN 5s AFTER removal from the tab list (a stable signal). */
    final java.util.Map<java.util.UUID, Long> latencyAfterRemoveCount = new java.util.HashMap<>();
    final TreeSet<String> scoreboardObjectives = new TreeSet<>();
    final TreeSet<String> worlds = new TreeSet<>();
    String brand = "?";
    List<Integer> joinInts;
    boolean sawJoin, sawCommandList;
    boolean autoProbingPaused; // see Prober: suspended after a run of consecutive timeouts (limbo/anti-bot?)
    final List<Long> baselineRtts = new ArrayList<>(); // RTT of a deliberately non-existent command — the reference for this phase
    long keepAliveCount; // for passive KeepAlive jitter statistics (see Analyzer.onKeepAlive)
    Long keepAliveFirstMs, keepAlivePrevMs;
    final List<Long> keepAliveIntervalsMs = new ArrayList<>();
    final List<Double> tpsSamples = new ArrayList<>(); // see Analyzer.onTpsSample / Session.onTimeUpdate

    // Update rates (packets/sec) as an extra "fingerprint" of animation/scoreboard plugins —
    // the numbers alone don't prove a specific plugin, just one more measurement for the report.
    long headerFooterCount;
    Long headerFooterFirstMs, headerFooterLastMs;
    long scoreUpdateCount;
    Long scoreUpdateFirstMs, scoreUpdateLastMs;

    // The vanish triple diff (see Analyzer.finalizeVanishTripleDiff):
    final LinkedHashMap<java.util.UUID, String> playerInfoAdded = new LinkedHashMap<>(); // uuid -> name (may be null)
    final java.util.Set<java.util.UUID> playerInfoRemoved = new java.util.HashSet<>();
    final java.util.Set<java.util.UUID> entitySpawned = new java.util.HashSet<>();
    final TreeSet<String> chatJoinNamesLower = new TreeSet<>();
    final TreeSet<String> chatLeaveNamesLower = new TreeSet<>();

    PhaseInfo(int index, long startMs, List<String> triggers) {
        this.index = index;
        this.startMs = startMs;
        this.triggers = triggers;
    }
}
