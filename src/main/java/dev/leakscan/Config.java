package dev.leakscan;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import net.minecraftforge.fml.loading.FMLPaths;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Config: <gameDir>/leakscan/config.json. Probe list: <gameDir>/leakscan/probes.txt ("~" = space). */
public final class Config {
    public boolean autoProbe = true;
    public boolean autoDefaultProbes = true;
    public boolean autoNamespaceProbes = true;   // after receiving the command tree: /<plugin>:
    public boolean autoRootArgProbes = false;    // "/<cmd> " for every root command (noisy)
    public int startDelayMs = 3000;              // pause after login before the first probe
    public int probeIntervalMs = 250;            // 4 packets/sec, well below Spigot limits
    public int probeTimeoutMs = 5000;
    public int maxProbes = 400;
    public int pauseAfterConsecutiveTimeouts = 8; // consecutive timeouts without a single answer — a sign of limbo/anti-bot or rate limiting
    /** The auto-probe pause is a TEMPORARY exponential backoff: 30s -> 60s -> 120s -> 240s (cap),
     * reset on the first answer. Rate-limited servers drop a noticeable share of tab-completes
     * (actually 34-86% on rate-limited servers), so a run of 8 timeouts happens there by chance —
     * the queue must continue by itself, not wait for a manual .ls probe. The canary probe did not
     * work: such servers never answer non-existent commands at all. 0 = disable auto-resume
     * (the pause lasts until manual action). */
    public int probePauseCanaryMs = 30_000;
    public boolean notifyInChat = true;
    public String label = "default-player";      // permission profile label (for comparing reports)
    public String externalCommandsFile = "";     // file with a command list from your other mod (one command per line)

    // Cross-session per-channel packet DB: <gameDir>/leakscan/channel-db/<server>.json.
    // Accumulated per host, not per session — so patterns are visible even if the server only sent
    // 1-2 packets in a channel during one session.
    public boolean channelPatternAnalysis = true;
    public int channelDbMaxSamplesPerChannel = 24; // how many DISTINCT payloads to keep per channel (exact duplicates don't add new ones)
    public int channelDbSampleBytes = 256;         // how many leading bytes of a payload to keep per sample

    // Extra probes for a command that IS in the tree but answers empty (looks like a block) —
    // we try a plausible 2nd-level argument and a light syntax mutation. Still purely read-only
    // tab-complete, nothing is executed.
    public boolean deepProbeOnEmpty = true;
    public List<String> deepProbeTokens = new ArrayList<>(java.util.Arrays.asList("LuckPerms", "EssentialsX", "WorldGuard"));

    // One deliberately non-existent command, always probed — an RTT reference within THIS session
    // (not cross-session statistics: too much noise — TPS, chunks, GC, network jitter).
    public boolean timingBaselineEnabled = true;
    public String timingBaselineProbe = "/leakscan_zqx9182_baseline_check";

    public boolean scanTeamPackets = true;      // the Team packet sometimes names a player who is not in the tab list
    public boolean scanSoundNamespace = true;   // an SPlaySoundPacket with a foreign namespace = the plugin is visible without a channel
    public boolean scanKeepAliveTiming = true;  // passive KeepAlive interval statistics (no ready-made conclusions)
    public boolean scanDimensionCodec = true;   // custom namespaces in the dimension/biome NBT from JoinGame
    public boolean resourcePackFingerprintDb = true; // the resource pack sha1 is cross-checked BETWEEN different hosts
    public boolean scanBossBar = true;          // boss bar text goes through the same leak-search rules
    public boolean scanScoreboardObjectives = true; // internal objective names (featherboard_x etc.)
    public boolean scanChatSenderUuid = true;   // the sender UUID in SChatPacket on "system" messages
    public boolean scanTpsFromTimeUpdate = true; // estimate the real TPS from world age increments
    public boolean vanishTripleDiff = true;     // chat join/leave <-> PlayerInfo ADD/REMOVE <-> player spawn/despawn

    // Silent mode: nothing automatic — auto-probes don't start on their own, no chat notifications
    // (.ls command replies still work — they are local). Checks are started manually: .ls probe defaults.
    public boolean silentMode = false;

    // A server-list ping BEFORE/during login to the same host the connection goes to (a separate
    // socket): version.name, favicon (sha1, a global cross-host DB), players.sample (hidden online),
    // Forge modinfo (the server mod list). Disable if the server's anti-bot dislikes extra connections.
    public boolean pingOnJoin = true;
    public int pingTimeoutMs = 4000;

    // Replacing the "leakscan" -> "optifine" string (same length) in the outgoing fml:handshake:
    // Forge servers receive the list of ALL client mods (ModList.get().getMods()) and write it to
    // their logs.
    public boolean hideFromFmlHandshake = true;

    // A global cross-host channel index: <gameDir>/leakscan/channel-db/_global.json
    // (channel -> which hosts + total packets; payload samples are taken from the host DBs).
    public boolean globalChannelIndex = true;

    // report.md is a compact digest (TL;DR + one line per finding); the full format is report-full.md.
    public boolean compactReport = true;

    private static Config instance;

    static Path dir() {
        return FMLPaths.GAMEDIR.get().resolve("leakscan");
    }

    static synchronized Config get() {
        if (instance == null) instance = load();
        return instance;
    }

    private static Config load() {
        Gson g = new GsonBuilder().setPrettyPrinting().create();
        Path p = dir().resolve("config.json");
        try {
            Files.createDirectories(dir());
            if (Files.exists(p)) {
                try (Reader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
                    Config c = g.fromJson(r, Config.class);
                    if (c != null) return c;
                }
            }
            Config c = new Config();
            Files.write(p, g.toJson(c).getBytes(StandardCharsets.UTF_8));
            return c;
        } catch (Exception e) {
            LeakScanMod.LOGGER.error("config load failed, using defaults", e);
            return new Config();
        }
    }

    private static final String[] DEFAULT_PROBES = {
        "/", "/bukkit:", "/minecraft:", "/spigot:", "/paper:", "/purpur:",
        "/pl~", "/plugins~", "/bukkit:pl~", "/bukkit:plugins~",
        "/version~", "/ver~", "/about~", "/icanhasbukkit~", "/bukkit:version~", "/bukkit:ver~", "/bukkit:about~",
        "/help~", "/?~", "/bukkit:help~", "/bukkit:?~",
        "/msg~", "/tell~", "/w~", "/whisper~", "/minecraft:msg~", "/minecraft:tell~",
        "/tp~", "/teleport~", "/tpa~", "/minecraft:tp~",
        "/execute in~", "/execute as~", "/scoreboard objectives remove~", "/team modify~", "/gamerule~",
        "/paper~", "/spark~", "/timings~", "/lp~", "/luckperms~", "/mv~", "/co~", "/ess~", "/essentials~", "/eco~"
    };

    /** Loads probes.txt (creates it on first run). "~" is replaced with a space. */
    static List<String> defaultProbes() {
        List<String> out = new ArrayList<>();
        Path p = dir().resolve("probes.txt");
        try {
            Files.createDirectories(dir());
            if (!Files.exists(p)) {
                StringBuilder sb = new StringBuilder("# one probe per line; '~' = space (trailing spaces are lost in chat/files)\n");
                for (String s : DEFAULT_PROBES) sb.append(s).append('\n');
                Files.write(p, sb.toString().getBytes(StandardCharsets.UTF_8));
            }
            for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                if (line.isEmpty() || line.startsWith("#")) continue;
                out.add(line.replace('~', ' '));
            }
        } catch (Exception e) {
            LeakScanMod.LOGGER.error("probes.txt load failed, using built-in list", e);
            out.clear();
            for (String s : DEFAULT_PROBES) out.add(s.replace('~', ' '));
        }
        return out;
    }
}
