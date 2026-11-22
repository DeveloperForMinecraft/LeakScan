package dev.leakscan;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Detects a change of "environment" (another backend behind a proxy, another limbo, or simply a
 * full re-initializing packet such as a dimension change) by packets that normally arrive once at
 * login and should not reappear mid-game.
 * <p>
 * A single packet is an unreliable marker. {@code JoinGame} is the only truly strong signal: it is
 * sent only on a real full re-login, never during normal play. {@code Respawn}, unlike it, also
 * flies on ordinary death/respawn and on portal transitions to the Nether/End on the SAME server —
 * that is not an environment change, so it does not trigger on its own.
 * <p>
 * IMPORTANT (refined in a real test): the vanilla world re-sync on an ordinary respawn/portal
 * drags along far more packets than expected — at least {@code PlayerAbilities} and
 * {@code ServerDifficulty} fly together with a perfectly ordinary Respawn in practice, so the
 * "Respawn + any of them" combination falsely triggered on every portal entry. That is why the
 * list of possible corroborants for Respawn is deliberately narrowed to {@code CommandList} only —
 * forwarding the command tree is NOT part of the world/dimension re-sync, it describes
 * permissions/plugins, i.e. it is the only one of the "weighted" packets with no evidence of
 * flying around during normal play. If even this turns out to be a false positive — let us know,
 * we will remove Respawn's weight entirely and leave JoinGame as the only trigger. Packets that
 * fly regularly during normal play anyway (scoreboard, player abilities, difficulty, held item,
 * world border) are deliberately not in the marker list.
 */
final class PhaseDetector {

    private static final Map<String, Integer> MARKERS = new LinkedHashMap<>();
    static {
        MARKERS.put("SJoinGamePacket", 2);
        MARKERS.put("SRespawnPacket", 1);
        MARKERS.put("SCommandListPacket", 1);
        // NOTHING else corroborates a Respawn: ServerDifficulty/PlayerAbilities/HeldItemChange/
        // WorldBorder/TagsList/UpdateRecipes turned out in practice to be part of the ordinary world
        // re-sync on respawn/portal (see the class header) — their joint appearance with Respawn
        // means nothing.
    }

    /**
     * If more than this has passed since the previous marker — a new packet burst has begun.
     */
    private static final long SETTLE_GAP_MS = 1200;
    /** Total burst weight at which a phase switch is declared (JoinGame triggers alone; Respawn — only with corroboration). */
    private static final int TRIGGER_WEIGHT = 2;
    /** Fast path without locking: 99.9% of packets are not markers. */
    private static final Set<String> MARKER_NAMES = new LinkedHashSet<>(java.util.Arrays.asList(
        "SJoinGamePacket", "SRespawnPacket", "SCommandListPacket"));

    private final Set<String> burst = new LinkedHashSet<>();
    private long lastMarkerMs;
    private long lastDeathMs = Long.MIN_VALUE;
    private boolean sessionStarted;
    /** true until the VERY FIRST marker burst (a normal login) closes — it is ignored entirely. */
    private boolean initialBurstActive = true;
    private boolean burstConsumed;
    private int phase;

    /**
     * Player death (SUpdateHealthPacket with health=0). A real vanilla test showed that on respawn
     * after death the server RE-SENDS the command tree — and the Respawn+CommandList pair was
     * falsely counted as a server switch. If a death was noticed within the last 30 s, a similar
     * burst is treated as an ordinary respawn.
     */
    synchronized void noteDeath(long now) {
        lastDeathMs = now;
    }

    synchronized int phase() {
        return phase;
    }

    /**
     * Called for every inbound packet (Netty thread). Returns the list of trigger packets if a
     * phase has just switched, otherwise {@code null}.
     */
    List<String> note(String packetType, long now) {
        if (!MARKER_NAMES.contains(packetType)) return null; // no monitor entry for 99.9% of packets
        return noteMarker(packetType, now);
    }

    private synchronized List<String> noteMarker(String packetType, long now) {
        Integer weight = MARKERS.get(packetType);
        if (weight == null) return null;

        boolean isFirstEver = !sessionStarted;
        boolean gapTooLarge = !isFirstEver && (now - lastMarkerMs > SETTLE_GAP_MS);
        if (isFirstEver || gapTooLarge) {
            burst.clear();
            burstConsumed = false;
            if (gapTooLarge) initialBurstActive = false; // a NEW burst has arrived, so the initial one has definitely closed
        }
        sessionStarted = true;
        lastMarkerMs = now;
        burst.add(packetType);

        // The entire very first burst of the connection is a normal login, not an environment change.
        if (initialBurstActive || burstConsumed) return null;

        int total = 0;
        for (String t : burst) total += MARKERS.get(t);
        if (total < TRIGGER_WEIGHT) return null;

        // A Respawn without JoinGame shortly after a detected death is an ordinary respawn: vanilla
        // re-sends the command tree after death (confirmed by the 2026-10-02 test), not a server switch.
        if (!burst.contains("SJoinGamePacket") && burst.contains("SRespawnPacket")
            && lastDeathMs != Long.MIN_VALUE && now - lastDeathMs < 30_000) {
            burstConsumed = true;
            return null;
        }

        burstConsumed = true;
        phase++;
        return new ArrayList<>(burst);
    }
}
