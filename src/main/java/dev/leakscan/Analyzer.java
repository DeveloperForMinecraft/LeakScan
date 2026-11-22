package dev.leakscan;

import com.mojang.brigadier.tree.CommandNode;
import net.minecraft.client.Minecraft;
import net.minecraft.client.network.play.ClientPlayNetHandler;
import net.minecraft.client.network.play.NetworkPlayerInfo;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Leak-search rules. Everything the sniffer/probers see arrives here. */
final class Analyzer {

    static final class ProbeStat {
        final int phase;
        final String probe;
        final int count;
        final long rttMs;
        final boolean timeout;
        final boolean retest; // a timing-candidate retest (not included in the base measurements' median)

        ProbeStat(int phase, String probe, int count, long rttMs, boolean timeout, boolean retest) {
            this.phase = phase;
            this.probe = probe;
            this.count = count;
            this.rttMs = rttMs;
            this.timeout = timeout;
            this.retest = retest;
        }
    }

    private static final class Rule {
        final String name;
        final Pattern pattern;
        final Severity severity;
        final String recommendation;

        Rule(String name, String regex, Severity severity, String recommendation) {
            this.name = name;
            this.pattern = Pattern.compile(regex);
            this.severity = severity;
            this.recommendation = recommendation;
        }
    }

    private static Set<String> set(String... a) {
        return new HashSet<>(Arrays.asList(a));
    }

    private static final Set<String> SOFTWARE_NS = set("minecraft", "bukkit", "spigot", "paper", "purpur",
        "pufferfish", "craftbukkit", "folia", "leaf");
    private static final Set<String> DEFAULT_WORLDS = set("minecraft:overworld", "minecraft:the_nether", "minecraft:the_end");
    private static final Set<String> PLUGIN_LISTERS = set("pl", "plugins", "bukkit:pl", "bukkit:plugins");
    private static final Set<String> VERSION_CMDS = set("version", "ver", "about", "icanhasbukkit",
        "bukkit:version", "bukkit:ver", "bukkit:about");
    private static final Set<String> HELP_CMDS = set("help", "?", "bukkit:help", "bukkit:?");
    private static final Set<String> PLAYER_CMDS = set("msg", "tell", "w", "whisper", "tp", "teleport", "tpa", "tpahere",
        "minecraft:msg", "minecraft:tell", "minecraft:w", "minecraft:tp", "minecraft:teleport");
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_]{3,16}"); // Mojang's actual name limits

    /** Lists from this size on are compared pairwise for near-duplicates (see noteBigList/nearDuplicates). */
    private static final int BIGLIST_MIN_SIZE = 15;
    private static final double BIGLIST_MIN_OVERLAP = 0.95;
    private static final int BIGLIST_MAX_DIFF = 60;
    /** From how many commands with an identical list it's worth mentioning separately (just for reference). */
    private static final int BIGLIST_MIN_IDENTICAL_GROUP = 10;
    /** If evidence has more items than this — save the full list as a separate file (see withFullListPointer). */
    private static final int FULL_LIST_POINTER_THRESHOLD = 150;

    private static final Map<String, String> CHANNEL_HINTS = new LinkedHashMap<>();
    private static final List<Rule> RULES = new ArrayList<>();

    private static final String REC_GENERIC = "Find the source of the string (a plugin / an error text / a kick message) and remove the technical details from what players see.";
    private static final String REC_TABCOMPLETE = "Filter tab-complete for players without permissions: intercept TabCompleteEvent/AsyncTabCompleteEvent (clear completions for service commands) "
        + "or filter the inbound tab-complete packet (a ProtocolLib/Via-like layer). Hiding commands from the tree (PlayerCommandSendEvent) does NOT protect against this. "
        + "Important: this leaks THE VERY FACT that a command/plugin and its syntax exist, not necessarily the permission to execute it — "
        + "execution may still hit a separate permission check, but an attacker no longer needs to guess it.";
    private static final String REC_CHANNEL = "Check whether the client needs the channel. Channel registration/handlers can be filtered at the proxy level or by a packet filter; "
        + "for brands/mod-detector channels — disable sending in the plugin's config if it supports that.";

    static {
        CHANNEL_HINTS.put("bungeecord", "a BungeeCord/Waterfall proxy in front of the server");
        CHANNEL_HINTS.put("velocity:", "a Velocity proxy");
        CHANNEL_HINTS.put("fml:", "Forge / mods on the server");
        CHANNEL_HINTS.put("forge:", "Forge / mods on the server");
        CHANNEL_HINTS.put("fabric", "Fabric API");
        CHANNEL_HINTS.put("worldinfo:", "a world-id for map mods (Xaero/VoxelMap/JourneyMap), often from a plugin");
        CHANNEL_HINTS.put("xaero", "Xaero's Minimap/World Map support");
        CHANNEL_HINTS.put("journeymap", "JourneyMap");
        CHANNEL_HINTS.put("voxelmap", "VoxelMap");
        CHANNEL_HINTS.put("wdl", "the World Downloader control channel");
        CHANNEL_HINTS.put("servux:", "Servux (data for MiniHUD)");
        CHANNEL_HINTS.put("floodgate", "Floodgate (Bedrock)");
        CHANNEL_HINTS.put("geyser", "Geyser (Bedrock)");
        CHANNEL_HINTS.put("voicechat:", "Simple Voice Chat");
        CHANNEL_HINTS.put("plasmo", "Plasmo Voice");
        CHANNEL_HINTS.put("luckperms:", "LuckPerms");
        CHANNEL_HINTS.put("vv:", "ViaVersion — hands out the server's NATIVE version (see the separate finding)");
        CHANNEL_HINTS.put("deluxemenus:", "DeluxeMenus (donation menu names)");
        CHANNEL_HINTS.put("luckperms:update", "LuckPerms messaging: sent to the FIRST online player without a registration check (sources) — vanilla clients receive it too");
        CHANNEL_HINTS.put("worldedit:cui", "WorldEdit (the CUI selection protocol)");
        CHANNEL_HINTS.put("authme:main", "AuthMe: login sync between servers — payload = event type + the PLAYER'S NAME");
        CHANNEL_HINTS.put("matrix:geyser", "Matrix AntiCheat (+Geyser): a channel marking Bedrock players; the payload contains names");
        CHANNEL_HINTS.put("lunarclient:pm", "LunarClient compatibility (something on the server is tailored to it)");
        CHANNEL_HINTS.put("vc:", "Simple Voice Chat in the pre-modern channel format (1.12-compat)");
        CHANNEL_HINTS.put("voicechat:", "Simple Voice Chat: the SecretPacket hands every player the voice server address, a personal secret and network settings");
        CHANNEL_HINTS.put("limboauth:", "LimboAuth (LimboAPI family); the channel suffix after mod/ looks like an installation instance id");

        RULES.add(new Rule("Internal IP", "\\b(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})\\b",
            Severity.HIGH, REC_GENERIC));
        RULES.add(new Rule("IP address", "\\b(?!10\\.|192\\.168\\.|127\\.|172\\.(?:1[6-9]|2\\d|3[01])\\.)(?:\\d{1,3}\\.){3}\\d{1,3}\\b",
            Severity.MEDIUM, REC_GENERIC));
        RULES.add(new Rule("Filesystem path", "(?i)(?:\\b[a-z]:\\\\[\\w\\\\. -]{3,}|/(?:home|root|opt|srv|var|usr|etc|mnt)/[\\w/.\\-]{2,})",
            Severity.HIGH, REC_GENERIC));
        RULES.add(new Rule("Internal class / stack trace",
            "(?:\\bat\\s+[\\w.$]+\\([\\w$]+\\.java:\\d+\\))|(?:\\b(?:org\\.bukkit|net\\.minecraft|com\\.mojang|io\\.papermc|co\\.aikar|org\\.spigotmc)\\.[\\w.$]+)",
            Severity.HIGH, REC_GENERIC));
        RULES.add(new Rule("Exception name", "\\b[A-Za-z_.]{3,}Exception\\b", Severity.MEDIUM, REC_GENERIC));
        RULES.add(new Rule("Build/software version string",
            "(?i)git-[\\w.-]+-\\d+|\\(MC: ?\\d+\\.\\d+(?:\\.\\d+)?\\)|\\bversion[: ]+\\d+\\.\\d+(?:\\.\\d+)+",
            Severity.MEDIUM, REC_GENERIC));
        RULES.add(new Rule("Possible secret", "(?i)\\b(?:password|passwd|secret|token|api[_-]?key)\\s*[:=]\\s*\\S{3,}",
            Severity.CRITICAL, REC_GENERIC));
        RULES.add(new Rule("Discord webhook", "(?i)discord(?:app)?\\.com/api/webhooks/\\d+/[\\w-]+", Severity.CRITICAL, REC_GENERIC));
        RULES.add(new Rule("URL", "(?i)https?://[^\\s\"'<>]+", Severity.LOW, REC_GENERIC));
        // A permission node in a denial message: reveals the exact permission name and therefore the
        // plugin's whole permission scheme. The regex keeps Russian keywords too — target servers
        // are often Russian-speaking.
        RULES.add(new Rule("Permission node in a message", "(?i)(?:permission|perm|право|нужно|требует|нет доступа)[^\\w\\n]{0,24}([a-z][a-z0-9_-]*(?:\\.[a-z0-9_-]+){2,})",
            Severity.MEDIUM, "A string visible to the player mentions an exact permission node (e.g. essentials.fly) — "
                + "that is the plugin's permission map. Remove the permission name from denial messages."));
    }

    private static final Pattern BUILD_INFO = Pattern.compile("(?i)git-|\\d+\\.\\d+|\\(|build");
    private static final Pattern PLUGIN_TAG = Pattern.compile("^\\s*\\[([^\\]]{2,24})\\]");
    private static final Pattern RESOURCE_LOCATION = Pattern.compile("([a-z0-9_.-]+):([a-z0-9_./-]+)");

    private final Session s;
    private final Map<String, Finding> findings = new LinkedHashMap<>();
    private final List<ProbeStat> stats = new ArrayList<>();
    /** Commands from your external collector mod: they survive phase switches, unlike rootCommands. */
    private final Set<String> externalCommands = new TreeSet<>();
    /** Phases (= environments/backends) within this connection. See PhaseDetector. */
    final List<PhaseInfo> phases = new ArrayList<>();
    volatile int currentPhase;

    /** Working sets of the CURRENT phase: used for leak detection, cleared on a phase switch. */
    final Set<String> channels = Collections.synchronizedSet(new TreeSet<String>());
    final Set<String> rootCommands = Collections.synchronizedSet(new TreeSet<String>());
    final Set<String> customSounds = Collections.synchronizedSet(new TreeSet<String>());
    volatile String brand;

    /** The player's own UUID (excluded from vanish checks) and session-wide PlayerInfo maps. */
    volatile java.util.UUID ownUuid;
    private final Set<UUID> everAddedUuid = Collections.synchronizedSet(new HashSet<>());
    private final Map<UUID, String> uuidToName = new java.util.concurrent.ConcurrentHashMap<>();

    /** phase -> probe -> a large suggestion list (see noteBigList/nearDuplicates: /ci vs /itemdb etc.). */
    private final Map<Integer, Map<String, List<String>>> bigLists = new LinkedHashMap<>();
    /** phase -> every name ever seen in the live tab list during the scan (not just "now", because by
     * the time finalizeBigListDiffs() runs on session close the connection may already be dead). */
    private final Map<Integer, Set<String>> everOnlineByPhase = new LinkedHashMap<>();
    /** Commands for which extra probes on an empty answer were already issued (see maybeDeepProbeOnEmpty) — to avoid loops. */
    private final Set<String> deepProbeAttempted = new HashSet<>();
    /** The exact text of deep probes awaiting an answer — by it we recognize that this is not an ordinary probe but a block-bypass attempt. */
    private final Set<String> deepProbeTexts = new HashSet<>();
    /** Timing candidates awaiting retests (x3): phase+probe -> how many repeats have been sent. */
    private final Map<String, Integer> timingRetesting = new LinkedHashMap<>();
    /** Retest measurements of a timing candidate: phase+probe -> the RTT list. */
    private final Map<String, List<Long>> timingRetestSamples = new LinkedHashMap<>();
    /** Candidates REFUTED by repeats (the outlier was a freeze) — the report removes them from anomalies. */
    private final Set<String> timingRejected = new HashSet<>();
    /** Candidates CONFIRMED by repeats (all 3 measurements steadily above the threshold). */
    private final Set<String> timingConfirmed = new HashSet<>();
    private static final int TIMING_RETESTS_PER_CANDIDATE = 3;
    private static final int TIMING_MAX_CANDIDATES = 8; // a per-session (not per-phase) limit: the key map is shared

    Analyzer(Session s) {
        this.s = s;
        phases.add(new PhaseInfo(0, System.currentTimeMillis(), Collections.<String>emptyList()));
    }

    /** Commands from your collector mod: kept separately so they survive a phase switch. */
    synchronized void addExternalCommands(Collection<String> names) {
        externalCommands.addAll(names);
        rootCommands.addAll(names);
    }

    /** Netty thread: called by PhaseDetector on a probable server/environment switch. */
    synchronized void beginPhase(int phase, long atMs, List<String> triggers) {
        currentPhase = phase;
        phases.add(new PhaseInfo(phase, atMs, triggers));
        rootCommands.clear();
        rootCommands.addAll(externalCommands);
        channels.clear();
        customSounds.clear();
    }

    private PhaseInfo phaseInfo() {
        return phases.get(Math.min(currentPhase, phases.size() - 1));
    }

    // ---------------------------------------------------------------- findings

    synchronized Finding add(Severity sev, String category, String title, Collection<String> evidence, String rec) {
        return add(currentPhase, sev, category, title, evidence, rec);
    }

    /** Like add(), but for a specific (possibly already closed) phase — needed for post-hoc analysis at session close. */
    synchronized Finding add(int phase, Severity sev, String category, String title, Collection<String> evidence, String rec) {
        String key = phase + "|" + category + "|" + title;
        Finding f = findings.get(key);
        boolean isNew = f == null;
        if (isNew) {
            f = new Finding(phase, sev, category, title, rec);
            findings.put(key, f);
        }
        f.hits++;
        for (String e : evidence) if (f.evidence.size() < 200) f.evidence.add(e);
        if (isNew && sev.ordinal() >= Severity.HIGH.ordinal()) s.alert(sev, title);
        return f;
    }

    /**
     * Like add(), but for findings of the form "/version, /ver, /about ...": if the evidence (the
     * suggestion list) matches an existing finding of the same category and phase BYTE-FOR-BYTE,
     * no duplicate is created — a label (e.g. another command alias) is appended to the existing
     * finding's title instead. template — a string with a single "%s" for join(labels, ", ").
     */
    synchronized Finding addGrouped(Severity sev, String category, String template, String label, Collection<String> evidence, String rec) {
        List<String> sorted = new ArrayList<>(evidence);
        Collections.sort(sorted);
        String key = currentPhase + "|" + category + "|content:" + String.join("\u0001", sorted);
        Finding f = findings.get(key);
        boolean isNew = f == null;
        if (isNew) {
            f = new Finding(currentPhase, sev, category, String.format(template, label), rec);
            findings.put(key, f);
        }
        f.hits++;
        f.mergeLabel(template, label);
        for (String e : evidence) if (f.evidence.size() < 200) f.evidence.add(e);
        if (isNew && sev.ordinal() >= Severity.HIGH.ordinal()) s.alert(sev, f.title);
        return f;
    }

    synchronized List<Finding> snapshot() {
        List<Finding> list = new ArrayList<>(findings.values());
        Collections.sort(list, (a, b) -> {
            if (a.phase != b.phase) return a.phase - b.phase;
            return b.severity.ordinal() - a.severity.ordinal();
        });
        return list;
    }

    synchronized List<ProbeStat> probeStats() {
        return new ArrayList<>(stats);
    }

    // ---------------------------------------------------------------- generic text patterns

    void scanText(String source, String text) {
        if (text == null || text.isEmpty()) return;
        if (text.length() > 20000) text = text.substring(0, 20000);
        for (Rule r : RULES) {
            Matcher m = r.pattern.matcher(text);
            int n = 0;
            while (m.find() && n++ < 10) {
                int a = Math.max(0, m.start() - 30), b = Math.min(text.length(), m.end() + 30);
                String snippet = text.substring(a, b).replace('\n', ' ');
                add(r.severity, "pattern", r.name + ": " + m.group(),
                    Collections.singletonList(source + ": ..." + snippet + "..."), r.recommendation);
            }
        }
    }

    /** The timing anomaly threshold: max(3×median, median+40 ms) over the phase's non-retest measurements. 0 = not enough data. */
    private long timingThreshold(int phase) {
        List<Long> rtts = new ArrayList<>();
        for (ProbeStat st : stats) {
            if (st.phase == phase && !st.timeout && !st.retest) rtts.add(st.rttMs);
        }
        if (rtts.size() < 5) return 0;
        Collections.sort(rtts);
        long median = rtts.get(rtts.size() / 2);
        return Math.max(3 * median, median + 40);
    }

    boolean isTimingRejected(int phase, String probe) {
        synchronized (this) {
            return timingRejected.contains(phase + "\u0001" + probe);
        }
    }

    boolean isTimingConfirmed(int phase, String probe) {
        synchronized (this) {
            return timingConfirmed.contains(phase + "\u0001" + probe);
        }
    }

    /**
     * Like scanText, but creates no findings — it just returns "rule name: match" — for offline
     * pattern analysis of channels (see ChannelPatternAnalyzer), where the finding is attached to a
     * specific phase separately and only the fact of a match is needed here.
     */
    static List<String> quickScan(String text) {
        List<String> hits = new ArrayList<>();
        if (text == null || text.isEmpty()) return hits;
        for (Rule r : RULES) {
            Matcher m = r.pattern.matcher(text);
            if (m.find()) hits.add(r.name + ": " + m.group());
        }
        return hits;
    }

    // ---------------------------------------------------------------- plugin messages

    void onChannel(String ch, byte[] data) {
        String lc = ch.toLowerCase();
        if (lc.equals("minecraft:brand") || lc.equals("mc|brand")) {
            onBrand(ByteUtil.readVarString(data));
            return;
        }
        if (lc.equals("minecraft:register") || lc.equals("register")) {
            for (String c : new String(data, StandardCharsets.UTF_8).split("\0")) {
                if (!c.isEmpty()) noteChannel(c);
            }
            return;
        }
        if (lc.equals("minecraft:unregister") || lc.equals("unregister")) return;
        if (lc.startsWith("vv:")) {
            noteChannel(ch);
            onViaDetails(ch, data);
            return;
        }
        if (lc.equals("voicechat:secret")) {
            noteChannel(ch);
            onVoicechatSecret(data);
            return;
        }
        noteChannel(ch);
        synchronized (this) {
            PhaseInfo p = phaseInfo();
            if (p.channelSamples.size() < 64 && !p.channelSamples.containsKey(ch)) {
                String prev = ByteUtil.preview(data, 120);
                if (!prev.isEmpty()) p.channelSamples.put(ch, prev);
            }
        }
        scanText("payload " + ch, ByteUtil.runs(data, 512));
    }

    /**
     * voicechat:secret (Simple Voice Chat, the format from SecretPacket.toBytes):
     * [secret 16B][port int][uuid 16B][codec byte][mtu int][distance double][keepAlive int]
     * [groups bool][varint-len + host utf][recording bool]. The main leak is voiceHost: a server
     * hiding behind a domain/proxy hands every player the BARE IP:port of the voice machine.
     */
    private void onVoicechatSecret(byte[] data) {
        try {
            if (data.length < 16 + 4 + 16 + 1 + 4 + 8 + 4 + 1 + 1 + 1) return;
            int pos = 16; // secret
            pos += 4;     // port (not read separately: it is also in the host below)
            pos += 16;    // player uuid
            pos += 1;     // codec
            pos += 4;     // mtu
            pos += 8;     // distance double
            pos += 4;     // keepAlive
            boolean groups = data[pos] != 0;
            pos += 1;
            int len = 0, shift = 0, x;
            do {
                x = data[pos++] & 0xFF;
                len |= (x & 0x7F) << shift;
                shift += 7;
            } while ((x & 0x80) != 0 && shift < 35);
            if (len < 0 || len > 256 || pos + len > data.length - 1) return;
            String host = new String(data, pos, len, StandardCharsets.UTF_8);
            boolean recording = data[pos + len] != 0;
            List<String> ev = new ArrayList<>();
            ev.add("voiceHost = " + host);
            ev.add("groupsEnabled = " + groups + ", allowRecording = " + recording);
            // a bare IP in voiceHost while connecting by domain = bypassing the domain/proxy
            boolean bareIp = host.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(:\\d+)?");
            boolean connByDomain = s.pingHost != null && !s.pingHost.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*");
            if (bareIp && connByDomain) {
                ev.add("connected via a domain (" + s.pingHost + "), but the voice server is a bare IP");
                add(Severity.HIGH, "software", "Simple Voice Chat reveals the machine's real IP: " + host, ev,
                    "Voice chat needs a direct UDP channel, so the address is handed to every player — and the "
                        + "domain/proxy stop hiding anything. Serve voice under a separate domain, or accept it: "
                        + "it is part of SVC's design.");
            } else {
                add(Severity.MEDIUM, "software", "Simple Voice Chat hands out the voice server address: " + host, ev,
                    "The address is given to every player by design (direct UDP is required). Check whether it "
                        + "exposes an internal/real address if you are masking behind a domain.");
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * ViaVersion tells the client the server's NATIVE version (ConnectionDetails.sendServerDetails,
     * confirmed by the sources): a server that speaks "1.16.5" on the wire may actually be 1.18+.
     * Real case from the logs: all three tested servers turned out to be
     * 1.18-1.18.1 behind ViaVersion.
     */
    private void onViaDetails(String ch, byte[] data) {
        try {
            com.google.gson.JsonObject o = new com.google.gson.Gson().fromJson(new String(data, StandardCharsets.UTF_8), com.google.gson.JsonObject.class);
            if (o == null || !o.has("version")) return;
            int nativeProtocol = o.get("version").getAsInt();
            String versionName = o.has("versionName") ? o.get("versionName").getAsString() : String.valueOf(nativeProtocol);
            if (nativeProtocol != 754) { // 754 = 1.16.5, our client's protocol
                List<String> ev = new ArrayList<>();
                ev.add("channel " + ch + ": " + ByteUtil.sanitizeInline(new String(data, StandardCharsets.UTF_8)));
                ev.add("the client connects as 1.16.5 (754), the server natively is: " + versionName + " (" + nativeProtocol + ")");
                if (o.has("platformName")) ev.add("platformName = " + o.get("platformName").getAsString());
                if (o.has("platformVersion")) ev.add("platformVersion = " + o.get("platformVersion").getAsString());
                add(Severity.MEDIUM, "software", "The server masquerades as 1.16.5; native version: " + versionName, ev,
                    "ViaVersion honestly reports the backend's real version to every client in the vv:server_details "
                        + "channel. It can only be hidden by disabling send-server-details in ViaVersion's config.");
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Login phase (before JoinGame). The fml:handshake channel carries S2CModList — the server's
     * FULL mod list: the vanilla client ignores it, and for an audit it is a ready map of the
     * server's software. Other channels (bungeecord:main etc.) are the same plugin channels, just
     * at the login stage.
     */
    synchronized void onLoginChannel(String ch, byte[] data) {
        String lc = ch.toLowerCase();
        if (lc.equals("fml:handshake")) {
            List<String> mods = parseFmlModList(data);
            if (mods != null && !mods.isEmpty()) {
                phaseInfo().serverMods.addAll(mods);
                add(Severity.HIGH, "software", "The Forge handshake reveals the server's mod list (" + mods.size() + ")",
                    new ArrayList<>(mods),
                    "The mod list is sent to ALL Forge clients at login (the login phase, the fml:handshake "
                        + "channel). It can only be hidden by sending it empty/faked at the fork or proxy level.");
            }
            return;
        }
        noteChannel(ch);
        scanText("login payload " + ch, ByteUtil.runs(data, 512));
    }

    /**
     * Parsing the fml:handshake payload (S2CModList): [varint count][count × varint-len strings].
     * If the format doesn't match (another handshake message or a changed format) — return null, no guessing.
     */
    private static List<String> parseFmlModList(byte[] data) {
        try {
            int pos = 0;
            // FMLLoginWrapper adds its own discriminator (a varint) before the message
            int disc = 0, shift = 0, x;
            do {
                if (pos >= data.length) return null;
                x = data[pos++] & 0xFF;
                disc |= (x & 0x7F) << shift;
                shift += 7;
            } while ((x & 0x80) != 0 && shift < 35);
            if (pos >= data.length) return null;
            int count = 0;
            shift = 0;
            do {
                if (pos >= data.length) return null;
                x = data[pos++] & 0xFF;
                count |= (x & 0x7F) << shift;
                shift += 7;
            } while ((x & 0x80) != 0 && shift < 35);
            if (count < 1 || count > 1000) return null;
            List<String> mods = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                int len = 0;
                shift = 0;
                do {
                    if (pos >= data.length) return null;
                    x = data[pos++] & 0xFF;
                    len |= (x & 0x7F) << shift;
                    shift += 7;
                } while ((x & 0x80) != 0 && shift < 35);
                if (len < 1 || len > 256 || pos + len > data.length) return null;
                String m = new String(data, pos, len, StandardCharsets.UTF_8);
                pos += len;
                if (!m.matches("[a-z0-9_.-]{2,64}")) return null; // a mod id — not garbage
                mods.add(m);
            }
            return mods;
        } catch (RuntimeException e) {
            return null;
        }
    }

    synchronized void onBrand(String b) {
        brand = b;
        phaseInfo().brand = b;
        if (!b.equalsIgnoreCase("vanilla")) {
            Severity sev = BUILD_INFO.matcher(b).find() ? Severity.HIGH : Severity.MEDIUM;
            add(sev, "software", "The server brand reveals software: " + b, Collections.singletonList("minecraft:brand = " + b),
                "Change/hide the brand (a proxy layer, a packet filter or a fork setting), or serve \"vanilla\".");
        }
        scanText("brand", b);
    }

    private synchronized void noteChannel(String name) {
        if (!channels.add(name)) return;
        phaseInfo().channels.add(name);
        // The channel finding is assembled as ONE item per phase at the end of the session (see
        // finalizeChannelFindings) — a separate entry per channel inflated the MEDIUM finding to a
        // dozen nearly identical items.
    }

    private static String channelHint(String name) {
        String low = name.toLowerCase();
        for (Map.Entry<String, String> e : CHANNEL_HINTS.entrySet()) {
            if (low.startsWith(e.getKey())) return e.getValue();
        }
        return null;
    }

    /** Main thread, before building the report (Session.close). One finding per phase instead of one per channel. */
    synchronized void finalizeChannelFindings() {
        for (PhaseInfo ph : phases) {
            List<String> ev = new ArrayList<>();
            for (String name : ph.channels) {
                if (name.toLowerCase().startsWith("minecraft:")) continue;
                String hint = channelHint(name);
                String sample = ph.channelSamples.get(name);
                String line = name + (hint != null ? " — probably: " + hint : " — an unknown channel; the namespace most likely matches a plugin/mod name");
                if (sample != null) {
                    String sv = ByteUtil.sanitizeInline(sample);
                    if (sv.length() > 100) sv = sv.substring(0, 100) + "...";
                    line += " | payload: \"" + sv + "\"";
                }
                ev.add(line);
            }
            if (!ev.isEmpty()) {
                add(ph.index, Severity.MEDIUM, "channel", "Plugin/mod channels are visible (" + ev.size() + ")", ev, REC_CHANNEL);
            }
            if (!ph.customSounds.isEmpty()) {
                add(ph.index, Severity.MEDIUM, "channel", "Custom plugin/mod sounds are visible (" + ph.customSounds.size() + ")",
                    new ArrayList<>(ph.customSounds),
                    "The namespace in a sound id usually matches the plugin/mod name — the same leak as via a "
                        + "plugin channel, only as a sound packet. Harder to hide: you would have to rename the "
                        + "sound files themselves in the resource pack.");
            }
            if (!ph.scoreboardObjectives.isEmpty()) {
                add(ph.index, Severity.LOW, "software", "Internal scoreboard objective names are visible (" + ph.scoreboardObjectives.size() + ")",
                    new ArrayList<>(ph.scoreboardObjectives),
                    "Internal objective names often match the scoreboard plugin's name (e.g. characteristic "
                        + "prefixes of known plugins) — informational, not always an intentional leak.");
            }
        }
    }

    // ---------------------------------------------------------------- command tree

    synchronized void onCommandTree(CommandNode<?> root) {
        Set<String> names = new TreeSet<>();
        for (CommandNode<?> n : root.getChildren()) names.add(n.getName().toLowerCase());
        rootCommands.addAll(names);
        phaseInfo().rootCommands.addAll(names);
        phaseInfo().sawCommandList = true;

        Map<String, List<String>> ns = new TreeMap<>();
        for (String n : names) {
            int i = n.indexOf(':');
            if (i > 0) ns.computeIfAbsent(n.substring(0, i), k -> new ArrayList<String>()).add(n.substring(i + 1));
        }
        List<String> pluginEv = new ArrayList<>();
        List<String> softEv = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : ns.entrySet()) {
            String line = e.getKey() + ": " + String.join(", ", ByteUtil.cap(e.getValue(), 30));
            if (SOFTWARE_NS.contains(e.getKey())) softEv.add(line);
            else pluginEv.add(line);
        }
        if (!pluginEv.isEmpty()) {
            add(Severity.MEDIUM, "plugins", "Plugins/mods give themselves away with namespace commands (" + pluginEv.size() + ")", pluginEv,
                "Hide namespaced commands (\"plugin:cmd\") from the players' tree: PlayerCommandSendEvent or a "
                    + "setting of your fork; check that tab-complete doesn't offer them either (see the probes).");
        }
        if (!softEv.isEmpty()) {
            add(Severity.LOW, "software", "Server software namespaces in the command tree", softEv,
                "Allows identifying the fork (paper:, purpur:, spigot: ...). Hidden the same way as plugin namespaced commands.");
        }
        s.prober.onCommandTree(new TreeSet<>(ns.keySet()), names);
    }

    // ---------------------------------------------------------------- join / resource pack / misc

    synchronized void onWorlds(List<String> worlds) {
        phaseInfo().worlds.addAll(worlds);
        phaseInfo().sawJoin = true;
        List<String> custom = new ArrayList<>();
        for (String w : worlds) if (!DEFAULT_WORLDS.contains(w)) custom.add(w);
        if (!custom.isEmpty()) {
            add(Severity.MEDIUM, "worlds", "Custom world names in the JoinGame packet", custom,
                "The world list is sent by the server itself at login. Minimize the number/names of loaded worlds or rewrite the packet at the proxy level.");
        }
    }

    synchronized void onJoinInts(List<Integer> ints) {
        phaseInfo().joinInts = ints;
    }

    synchronized void markProbingPaused(int phase) {
        if (phase < phases.size()) phases.get(phase).autoProbingPaused = true;
    }

    synchronized void noteBaselineRtt(int phase, long rttMs) {
        if (phase < phases.size()) phases.get(phase).baselineRtts.add(rttMs);
    }

    void onResourcePack(String url, String hash) {
        Severity sev = Severity.MEDIUM;
        try {
            String host = new URI(url).getHost();
            if (host != null && (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") || host.equals("localhost")
                || host.endsWith(".local") || host.endsWith(".internal"))) {
                sev = Severity.HIGH;
            }
        } catch (Exception ignored) {
        }
        add(sev, "resourcepack", "The resource pack hosting address is visible to the client: " + url,
            Arrays.asList("url = " + url, "sha1 = " + hash),
            "Use a public CDN domain without internal names/IPs and tokens in the URL.");

        if (s.rpFingerprintDb != null && hash != null && !hash.isEmpty()) {
            Set<String> otherHosts;
            synchronized (s.rpFingerprintDb) {
                otherHosts = s.rpFingerprintDb.recordAndCheck(hash, s.hostKey, url);
                ResourcePackFingerprintDb.save(s.rpFingerprintDb);
            }
            if (!otherHosts.isEmpty()) {
                List<String> ev = new ArrayList<>();
                ev.add("sha1 = " + hash);
                ev.add("this host: " + s.hostKey);
                for (String h : otherHosts) ev.add("already seen on: " + h);
                add(Severity.HIGH, "resourcepack", "The same resource pack (sha1) was already seen on another server",
                    ev, "A byte-for-byte identical resource pack on different hosts/IPs is a strong sign of the "
                        + "same operator/network under another brand (changing the name and IP is easy; redrawing "
                        + "custom donation textures from scratch — almost nobody will).");
            }
        }
    }

    /** Main thread (called by PingProbe via mc.execute). A pre-login server-list ping snapshot. */
    void onPingResult(String versionName, int online, int max, List<String> sampleNames,
                      String faviconSha1, List<String> forgeMods, String rawJson) {
        s.pingVersionName = versionName;
        s.pingFaviconSha1 = faviconSha1;
        s.pingSampleNames = sampleNames == null ? java.util.Collections.<String>emptyList() : sampleNames;
        if (versionName != null && !versionName.equalsIgnoreCase("vanilla") && !versionName.matches("(?i)1\\.16(\\.\\d)?")) {
            add(Severity.MEDIUM, "software", "The ping version name reveals software: " + versionName,
                java.util.Collections.singletonList("ping version.name = " + versionName),
                "The version.name string from the server-list ping is visible without joining; forks and proxies "
                    + "write their own name there. Change it to a standard one or hide it at the proxy level.");
        }
        if (forgeMods != null && !forgeMods.isEmpty()) {
            phaseInfo().serverMods.addAll(forgeMods);
            add(Severity.HIGH, "software", "The Forge ping gave out the server's mod list (" + forgeMods.size() + ")",
                new ArrayList<>(forgeMods),
                "The modinfo field in the server-list ping is available to everyone without joining. It can only "
                    + "be hidden at the fork/proxy level (or by removing the NetworkChannels Forge builds it from).");
        }
        List<String> ev = new ArrayList<>();
        if (versionName != null) ev.add("version.name = " + versionName);
        ev.add("online/max = " + online + "/" + max);
        if (sampleNames != null && !sampleNames.isEmpty()) ev.add("players.sample = " + joinCapped(sampleNames, 12));
        if (faviconSha1 != null) ev.add("favicon sha1 = " + faviconSha1);
        if (rawJson != null && rawJson.length() > 400) rawJson = rawJson.substring(0, 400) + "...";
        if (rawJson != null) ev.add("raw response: " + rawJson);
        add(Severity.INFO, "software", "Pre-login ping snapshot of the server", ev,
            "For reference: what the server says about itself even BEFORE login (the server list ping).");
        if (faviconSha1 != null && s.rpFingerprintDb != null) {
            Set<String> otherHosts;
            synchronized (s.rpFingerprintDb) {
                otherHosts = s.rpFingerprintDb.recordAndCheck(faviconSha1, s.hostKey, "(ping favicon)");
                ResourcePackFingerprintDb.save(s.rpFingerprintDb);
            }
            if (!otherHosts.isEmpty()) {
                List<String> fev = new ArrayList<>();
                fev.add("favicon sha1 = " + faviconSha1);
                fev.add("this host: " + s.hostKey);
                for (String h : otherHosts) fev.add("already seen on: " + h);
                add(Severity.HIGH, "software", "The same ping favicon was already seen on another server",
                    fev, "A byte-for-byte identical server icon on different hosts is a strong sign of the same "
                        + "network/operator under another brand (same as the resource pack sha1 fingerprint).");
            }
        }
    }

    void onTeamPacket(String teamName, List<String> names) {
        if (!s.cfg.scanTeamPackets) return;
        if (teamName != null && teamName.matches("\\d{1,3}[_-].*")) {
            add(Severity.LOW, "software", "The scoreboard team name suggests forced tab-list sorting: " + teamName,
                Collections.singletonList("team = " + teamName),
                "A numeric prefix in a team name (\"00_\", \"01_\"...) is a typical trick of tab-list sorting "
                    + "plugins (TAB and the like); it reveals their presence by itself.");
        }
        Set<String> online = onlineNames();
        if (online.isEmpty()) return; // nothing to compare with — we don't risk a false positive
        List<String> suspicious = new ArrayList<>();
        for (String n : names) {
            if (!USERNAME.matcher(n).matches()) continue;
            if (!online.contains(n.toLowerCase())) suspicious.add(n);
        }
        if (!suspicious.isEmpty()) {
            // Mass hiding of dozens of names is lobby/BotFilter design (the whole tab is hidden
            // intentionally; caught in the field: 20 team packets, 200 names in a lobby). One or
            // two extra names are far more interesting: that looks like a targeted vanish.
            boolean mass = suspicious.size() > 30;
            add(mass ? Severity.MEDIUM : Severity.HIGH, "players",
                mass ? "The tab list is mass-hidden, but team packets name " + suspicious.size() + " names (lobby/filter?)"
                     : "The team packet names player(s) who are not in the tab list",
                suspicious,
                mass
                    ? "Looks like a lobby/BotFilter phase where the tab is hidden entirely by design while "
                        + "scoreboard teams are still broadcast. For an audit it is still an environment "
                        + "fingerprint, but it doesn't smell like targeted player vanishing."
                    : "Looks like a hidden/vanish player leaking through a scoreboard team update (e.g. so that "
                        + "their own prefix renders correctly). Note: a race is possible during an ordinary "
                        + "join/leave — if it coincided with someone's connect, it may have been a false positive.");
        }
    }

    void onScoreboardObjective(String name) {
        if (!s.cfg.scanScoreboardObjectives) return;
        if (!phaseInfo().scoreboardObjectives.add(name)) return;
        // The internal objective name names the plugin outright (a constant in TAB's sources:
        // OBJECTIVE_NAME = "TAB-Scoreboard"), confirmed by decompilation/sources.
        if (name.startsWith("TAB-")) {
            add(Severity.LOW, "software", "The scoreboard objective '" + name + "' reveals the TAB plugin",
                Collections.singletonList("objective = " + name),
                "TAB hardcodes the objective name — change it in its config (scoreboard title/objective name), "
                    + "otherwise plugin identification is free for any client.");
        }
    }

    synchronized void onSystemMessageWithSender(String text, UUID sender) {
        if (!s.cfg.scanChatSenderUuid) return;
        List<String> ev = new ArrayList<>();
        ev.add("sender uuid = " + sender);
        ev.add("text: " + (text.length() > 200 ? text.substring(0, 200) + "..." : text));
        String knownName = phaseInfo().playerInfoAdded.get(sender);
        if (knownName != null) ev.add("this is a player's UUID: " + knownName);
        add(Severity.MEDIUM, "players", "A \"system\" message was sent on behalf of a specific player (sender UUID)", ev,
            "Truly automatic messages (a console broadcast, a scheduled plugin task) have a zero sender "
                + "UUID — the console/timer simply has nothing to attach, so they should NOT trigger this. A "
                + "non-zero UUID here usually means a PLAYER sent the message — e.g. an admin ran /say — and "
                + "the server attached their identity to what looks like an official announcement.");
    }

    void onChatJoin(String name) {
        if (!s.cfg.vanishTripleDiff) return;
        synchronized (this) {
            phaseInfo().chatJoinNamesLower.add(name.toLowerCase());
        }
    }

    void onChatLeave(String name) {
        if (!s.cfg.vanishTripleDiff) return;
        synchronized (this) {
            phaseInfo().chatLeaveNamesLower.add(name.toLowerCase());
        }
    }

    synchronized void onPlayerInfoAdd(List<UUID> uuids, Map<UUID, String> names) {
        if (!s.cfg.vanishTripleDiff) return;
        PhaseInfo p = phaseInfo();
        p.playerInfoAdded.putAll(names);
        for (UUID u : uuids) {
            p.playerInfoAdded.putIfAbsent(u, null);
            everAddedUuid.add(u);
        }
        for (Map.Entry<UUID, String> en : names.entrySet()) {
            if (en.getValue() != null) uuidToName.put(en.getKey(), en.getValue());
        }
    }

    synchronized void onPlayerInfoRemove(List<UUID> uuids) {
        if (!s.cfg.vanishTripleDiff) return;
        PhaseInfo p = phaseInfo();
        long now = System.currentTimeMillis();
        for (UUID u : uuids) {
            p.playerInfoRemoved.add(u);
            p.playerInfoRemovedAt.putIfAbsent(u, now);
        }
    }

    /**
     * UPDATE_LATENCY: vanish plugins often forget to filter ping updates for hidden players. A
     * single packet right after a REMOVE is a tab re-sync at a phase switch (a false positive,
     * caught in the field: even the player themselves got in). The honest signal is a ping that
     * continues SUSTAINED (>5 s after removal, 3+ times) or a uuid that was never in any phase's tab.
     */
    synchronized void onPlayerInfoLatency(List<UUID> uuids) {
        if (!s.cfg.vanishTripleDiff) return;
        PhaseInfo p = phaseInfo();
        long now = System.currentTimeMillis();
        for (UUID u : uuids) {
            p.latencyCount.merge(u, 1L, Long::sum);
            Long removedAt = p.playerInfoRemovedAt.get(u);
            if (removedAt != null && now - removedAt > 5_000) {
                p.latencyAfterRemoveCount.merge(u, 1L, Long::sum);
            }
        }
    }

    synchronized void onEntitySpawn(UUID id) {
        if (!s.cfg.vanishTripleDiff) return;
        phaseInfo().entitySpawned.add(id);
    }

    synchronized void onTpsSample(double tps) {
        phaseInfo().tpsSamples.add(tps);
    }

    synchronized void onHeaderFooterPacket(long now) {
        PhaseInfo p = phaseInfo();
        if (p.headerFooterFirstMs == null) p.headerFooterFirstMs = now;
        p.headerFooterLastMs = now;
        p.headerFooterCount++;
    }

    synchronized void onScoreUpdatePacket(long now) {
        PhaseInfo p = phaseInfo();
        if (p.scoreUpdateFirstMs == null) p.scoreUpdateFirstMs = now;
        p.scoreUpdateLastMs = now;
        p.scoreUpdateCount++;
    }

    /**
     * Main thread, before building the report (Session.close). The triple diff: a player entity
     * physically spawned (visible to nearby players) but was never in PlayerInfo (the tab list) —
     * the strongest vanish leak signal: the model/hitbox is visible although the tab hiding worked.
     * Weaker: the player appeared in the tab list but there was no public "X joined the game" — may
     * just be a custom/disabled join message, not necessarily vanish.
     */
    synchronized void finalizeVanishTripleDiff() {
        if (!s.cfg.vanishTripleDiff) return;
        // The ping sample vs the tab: names from players.sample never seen in the tab NOR in the
        // suggestion lists during the WHOLE session — a candidate for hidden online (or they simply
        // left before we joined).
        if (!s.pingSampleNames.isEmpty()) {
            Set<String> everSeen = new HashSet<>();
            for (PhaseInfo p : phases) {
                for (String n : p.playerInfoAdded.values()) if (n != null) everSeen.add(n.toLowerCase());
            }
            for (Set<String> online : everOnlineByPhase.values()) everSeen.addAll(online);
            List<String> ghost = new ArrayList<>();
            for (String n : s.pingSampleNames) {
                if (n == null || n.isEmpty()) continue;
                // servers put decorative §-strings into players.sample instead of names —
                // those are not players (caught in the field: "§6§l §2§lD§2§lE..."), filter by name format
                if (!isUsernameShaped(n)) continue;
                if (!everSeen.contains(n.toLowerCase())) ghost.add(n);
            }
            if (!ghost.isEmpty()) {
                add(0, Severity.MEDIUM, "players", "The ping sample contains players never seen in the tab during the session",
                    ghost,
                    "The server-list ping gives up to 12 random online names. Someone who never appeared in the "
                        + "tab during the whole session is a possible hidden player; but the sample is taken BEFORE "
                        + "login and the name may have simply left — re-check manually before drawing conclusions.");
            }
        }
        for (PhaseInfo ph : phases) {
            List<String> onlyEntity = new ArrayList<>();
            for (UUID id : ph.entitySpawned) {
                if (!ph.playerInfoAdded.containsKey(id)) onlyEntity.add(id.toString());
            }
            if (!onlyEntity.isEmpty()) {
                // NPC plugins (Citizens and the like) create EXACTLY the same entities: player-type,
                // without a PlayerInfo entry — that is their normal behavior, not a leak. If there are
                // many "phantoms" at once it is almost certainly NPCs, not a mass vanish, so both the
                // severity and the wording are softened.
                boolean manyNpcLike = onlyEntity.size() >= 3;
                Severity sev = manyNpcLike ? Severity.LOW : Severity.HIGH;
                String npcCaveat = manyNpcLike
                    ? "There are " + onlyEntity.size() + " of them at once — this looks much more like NPCs from "
                        + "a plugin like Citizens (NPCs have exactly the same signature: a player-type entity "
                        + "without PlayerInfo) than a mass vanish. "
                    : "If the server has an NPC plugin (Citizens and the like), this is expected for them too and "
                        + "not necessarily vanish: NPCs also spawn as player entities without a PlayerInfo entry. ";
                add(ph.index, sev, "players",
                    "A player entity physically spawned but was never in PlayerInfo (the tab list)", onlyEntity,
                    npcCaveat + "Excluding NPCs, this is the strongest vanish leak signal this mod can produce: "
                        + "the player's model/hitbox renders and is visible to nearby players although they are "
                        + "correctly hidden from the tab list. Check manually which UUID it is and whether a real "
                        + "online player with the same name exists elsewhere.");
            }
            // Hidden players with live latency updates. A single packet after a REMOVE is a re-sync
            // at a phase switch (in the field even the player themselves was caught by it); the honest
            // signal is a ping continuing steadily (>5s after removal, 3+ times), or a uuid that was
            // never in any phase's tab. Publicly departed players ("left the game") are excluded.
            Set<String> leftPublicly = new HashSet<>();
            for (PhaseInfo p2 : phases) leftPublicly.addAll(p2.chatLeaveNamesLower);
            List<String> latencyHidden = new ArrayList<>();
            for (Map.Entry<UUID, Long> en : ph.latencyAfterRemoveCount.entrySet()) {
                if (en.getValue() < 3) continue;
                UUID id = en.getKey();
                if (id.equals(ownUuid)) continue;
                String name = uuidToName.get(id);
                if (name != null && leftPublicly.contains(name.toLowerCase())) continue;
                latencyHidden.add((name != null ? name : id.toString())
                    + " — the ping kept updating " + en.getValue() + " more times after removal from the tab");
            }
            for (Map.Entry<UUID, Long> en : ph.latencyCount.entrySet()) {
                if (en.getValue() < 3) continue;
                UUID id = en.getKey();
                if (id.equals(ownUuid) || everAddedUuid.contains(id)) continue;
                latencyHidden.add(id + " — never in any phase's tab, yet the ping updated "
                    + en.getValue() + " times (NPCs have no live ping)");
            }
            if (!latencyHidden.isEmpty()) {
                add(ph.index, Severity.HIGH, "players",
                    "Hidden players keep receiving latency updates (UPDATE_LATENCY)", latencyHidden,
                    "The server sends ping updates for UUIDs that are not (or are no longer) in the tab list — "
                        + "so the player's connection is alive: that is the handwriting of a vanish plugin that "
                        + "hid the tab entry but didn't stop the update broadcast. Only SUSTAINED signals are "
                        + "shown here (3+ updates more than 5 s after removal); single re-sync packets are filtered out.");
            }
            if (!ph.chatJoinNamesLower.isEmpty()) { // only compare if join-message parsing found anything in this phase at all
                List<String> addedWithoutJoinMsg = new ArrayList<>();
                for (Map.Entry<UUID, String> e : ph.playerInfoAdded.entrySet()) {
                    String name = e.getValue();
                    if (name == null) continue;
                    if (!ph.chatJoinNamesLower.contains(name.toLowerCase())) addedWithoutJoinMsg.add(name);
                }
                if (!addedWithoutJoinMsg.isEmpty()) {
                    add(ph.index, Severity.MEDIUM, "players",
                        "Player(s) added to the tab list without a public \"X joined the game\"", addedWithoutJoinMsg,
                        "A weaker signal than the previous one: it may just be a custom/disabled join message "
                            + "from a plugin, not necessarily vanish. Worth re-checking manually.");
                }
            }
        }
    }

    void onSoundResource(String id) {
        if (!s.cfg.scanSoundNamespace) return;
        String lc = id.toLowerCase();
        if (lc.startsWith("minecraft:")) return;
        if (!customSounds.add(id)) return;
        // synchronized: the phase-specific TreeSets are written from the netty thread and read by
        // the main thread (finalize*).
        synchronized (this) {
            phaseInfo().customSounds.add(id);
        }
    }

    void onKeepAlive(long now) {
        synchronized (this) {
            PhaseInfo p = phaseInfo();
            if (p.keepAlivePrevMs != null) p.keepAliveIntervalsMs.add(now - p.keepAlivePrevMs);
            p.keepAlivePrevMs = now;
            p.keepAliveCount++;
        }
    }

    /** JoinGame carries the full dimension codec — a foreign namespace is visible there even if
     * minecraft:brand is faked as "vanilla" (custom dimensions/biomes can't be hidden that easily). */
    void onDimensionCodec(List<String> nbtDumps) {
        if (!s.cfg.scanDimensionCodec) return;
        Set<String> namespaces = new TreeSet<>();
        for (String dump : nbtDumps) {
            if (dump == null) continue;
            Matcher m = RESOURCE_LOCATION.matcher(dump);
            while (m.find()) {
                String ns = m.group(1);
                if (!ns.equals("minecraft")) namespaces.add(ns);
            }
        }
        if (!namespaces.isEmpty()) {
            add(Severity.MEDIUM, "software", "The dimension codec contains a foreign namespace: " + String.join(", ", namespaces),
                Collections.singletonList("namespaces: " + String.join(", ", namespaces)),
                "Custom dimensions/biomes (a datapack/mod) are visible in the JoinGame NBT structure even if "
                    + "minecraft:brand is faked as vanilla — the namespace is harder to hide here than the brand string.");
        }
    }

    void onChatText(String text) {
        scanText("chat/system", text);
        Matcher m = PLUGIN_TAG.matcher(text);
        if (m.find()) {
            add(Severity.LOW, "plugins", "The message prefix looks like a plugin name: [" + m.group(1) + "]",
                Collections.singletonList(text.length() > 120 ? text.substring(0, 120) : text),
                "Informational: message prefixes often match the plugin name.");
        }
    }

    // ---------------------------------------------------------------- probes

    void onProbeTimeout(String probe) {
        synchronized (this) {
            stats.add(new ProbeStat(currentPhase, probe, 0, -1, true, false));
            deepProbeTexts.remove(probe); // no answer will come — the "awaiting a deep probe" mark is no longer needed
        }
        s.reporter.probe(ByteUtil.kv("phase", currentPhase, "probe", probe, "timeout", true));
    }

    /** Main thread (needs access to the player list). */
    void onProbeResult(String probe, List<String> sug, List<String> tips, long rttMs) {
        onProbeResult(probe, sug, tips, rttMs, false);
    }

    /**
     * Main thread. retest=true — a timing-candidate retest: the texts/suggestions are not parsed
     * again (already parsed by the first measurement), only the RTT matters.
     */
    void onProbeResult(String probe, List<String> sug, List<String> tips, long rttMs, boolean retest) {
        int phase = currentPhase;
        if (retest) {
            boolean decided = false;
            synchronized (this) {
                stats.add(new ProbeStat(phase, probe, sug.size(), rttMs, false, true));
                String key = phase + "\u0001" + probe;
                List<Long> samples = timingRetestSamples.computeIfAbsent(key, k -> new ArrayList<>());
                samples.add(rttMs);
                if (samples.size() >= TIMING_RETESTS_PER_CANDIDATE) {
                    List<Long> sorted = new ArrayList<>(samples);
                    Collections.sort(sorted);
                    long retestMedian = sorted.get(sorted.size() / 2);
                    long threshold = timingThreshold(phase);
                    if (threshold > 0 && retestMedian > threshold) {
                        timingConfirmed.add(key);
                        add(phase, Severity.MEDIUM, "timing",
                            "A confirmed timing candidate: '" + probe.trim() + "' is steadily slower than the rest",
                            java.util.Arrays.asList(
                                "repeat measurements, ms: " + samples,
                                "the repeat median: " + retestMedian + " ms, threshold: " + threshold + " ms (max(3×median, median+40))"),
                            "Three repeated probes produced a median above the threshold — this is not a single "
                                + "freeze. A difference in answer time between commands may reveal the fact of "
                                + "processing (e.g. that the command exists and its arguments are parsed). Check "
                                + "what exactly slows the answer down.");
                    } else {
                        timingRejected.add(key); // the outlier was a freeze — removed from the report
                    }
                    decided = true;
                }
            }
            if (decided) s.reporter.probe(ByteUtil.kv("phase", phase, "probe", probe, "event",
                timingConfirmed.contains(phase + "\u0001" + probe) ? "timing-confirmed" : "timing-rejected",
                "samplesMs", rttMs));
            return;
        }

        synchronized (this) {
            stats.add(new ProbeStat(phase, probe, sug.size(), rttMs, false, false));
        }
        if (s.cfg.timingBaselineEnabled && probe.equals(s.cfg.timingBaselineProbe + " ")) {
            noteBaselineRtt(phase, rttMs);
        }
        // A timing candidate (RTT above the threshold): send 3 repeats — they don't eat the probe budget.
        if (!sug.isEmpty()) {
            long threshold;
            String key = phase + "\u0001" + probe;
            synchronized (this) {
                threshold = timingThreshold(phase);
            }
            if (threshold > 0 && rttMs > threshold) {
                boolean schedule = false;
                synchronized (this) {
                    if (!timingRetesting.containsKey(key) && !timingRejected.contains(key)
                        && !timingConfirmed.contains(key) && timingRetesting.size() < TIMING_MAX_CANDIDATES) {
                        timingRetesting.put(key, 0);
                        schedule = true;
                    }
                }
                if (schedule) s.prober.enqueueRetests(probe, TIMING_RETESTS_PER_CANDIDATE);
            }
        }
        List<String> tipList = new ArrayList<>();
        for (String t : tips) if (t != null && !t.isEmpty()) tipList.add(t);
        Map<String, Object> rec = ByteUtil.kv("phase", phase, "probe", probe, "rttMs", rttMs, "count", sug.size(),
            "suggestions", ByteUtil.cap(sug, 300));
        if (sug.size() > 300) {
            // Previously lists like 2794 suggestions on "/" were silently cut to 300 and the full
            // version existed NOWHERE (neither here nor in findings.json) — now the whole thing
            // lives in full-lists/.
            String path = s.reporter.saveFullList(probe.trim(), sug);
            if (path != null) rec.put("fullListFile", path);
        }
        if (!tipList.isEmpty()) rec.put("tooltips", ByteUtil.cap(tipList, 100));
        s.reporter.probe(rec);

        String src = "tab-complete '" + probe.trim() + "'";
        for (String x : ByteUtil.cap(sug, 300)) scanText(src, x);
        for (String x : ByteUtil.cap(tipList, 100)) scanText("tooltip " + src, x);

        String raw = probe.startsWith("/") ? probe.substring(1) : probe;
        String low = raw.toLowerCase();
        int sp = low.indexOf(' ');
        String cmd = sp < 0 ? low : low.substring(0, sp);
        String args = sp < 0 ? null : low.substring(sp + 1);

        List<String> clean = new ArrayList<>();
        for (String x : sug) clean.add(x.startsWith("/") ? x.substring(1) : x);

        // IMPORTANT: the key is the exact, NOT trim()'ed probe. The double trailing space
        // ("/version  ") is one of the tried mutations (see maybeDeepProbeOnEmpty); after trim() it
        // would be indistinguishable from an ordinary "/version" and the dedup would break.
        boolean wasDeepProbe;
        synchronized (this) {
            wasDeepProbe = deepProbeTexts.remove(probe);
        }
        if (wasDeepProbe) {
            if (!sug.isEmpty() && !looksLikePlayerFallback(clean)) {
                addGrouped(Severity.HIGH, "plugins",
                    "The block is bypassed by an extra argument/syntax mutation (case, an extra space) — the list is still visible: %s",
                    probe.trim(), withFullListPointer(probe.trim(), clean),
                    "The blocking plugin's check apparently compares the command buffer literally (case/exactly "
                        + "one space) rather than using the normalization Bukkit/Brigadier itself applies when "
                        + "parsing. Normalize the input (toLowerCase, trim, collapse spaces) before comparing in "
                        + "TabCompleteEvent/AsyncTabCompleteEvent.");
            }
            return;
        }

        if (sug.isEmpty()) {
            maybeDeepProbeOnEmpty(cmd, args);
            return;
        }

        noteBigList(probe, clean);
        noteOnlineSnapshot(phase, onlineNames());

        if (args != null) {
            if (VERSION_CMDS.contains(cmd) && args.isEmpty()) {
                if (!looksLikePlayerFallback(clean)) {
                    addGrouped(Severity.HIGH, "plugins", "The plugin list leaks via tab-complete: %s", "/" + cmd,
                        withFullListPointer("/" + cmd, clean), REC_TABCOMPLETE);
                }
            } else if (PLUGIN_LISTERS.contains(cmd)) {
                if (!looksLikePlayerFallback(clean)) {
                    addGrouped(Severity.HIGH, "plugins", "Answers tab-complete (looks like a plugin list): %s", "/" + cmd,
                        withFullListPointer("/" + cmd, clean), REC_TABCOMPLETE);
                }
            } else if (HELP_CMDS.contains(cmd) && args.isEmpty()) {
                if (!looksLikePlayerFallback(clean)) {
                    addGrouped(Severity.MEDIUM, "commands", "Topics via tab-complete (may include plugin names): %s", "/" + cmd,
                        withFullListPointer("/" + cmd, clean), REC_TABCOMPLETE);
                }
            } else if (PLAYER_CMDS.contains(cmd) && args.isEmpty()) {
                hiddenPlayers(cmd, clean);
            } else if (cmd.equals("execute") && args.equals("in ")) {
                List<String> custom = new ArrayList<>();
                for (String w : clean) if (!DEFAULT_WORLDS.contains(w.toLowerCase())) custom.add(w);
                if (!custom.isEmpty()) {
                    add(Severity.MEDIUM, "worlds", "World names via tab-complete /execute in", custom, REC_TABCOMPLETE);
                }
            } else if (!cmd.isEmpty() && !rootCommands.isEmpty() && !rootCommands.contains(cmd) && !looksLikePlayerFallback(clean)) {
                List<String> realCmds = withoutGarbageTokens(clean);
                if (!realCmds.isEmpty()) {
                    addGrouped(Severity.MEDIUM, "commands", "Hidden commands answer tab-complete: %s", "/" + cmd,
                        withFullListPointer("/" + cmd, realCmds), REC_TABCOMPLETE);
                }
            }
        } else if (!rootCommands.isEmpty()) {
            List<String> extra = new ArrayList<>();
            for (String c : clean) if (!rootCommands.contains(c.toLowerCase())) extra.add(c);
            extra = withoutGarbageTokens(extra); // the server sometimes answers with garbage like ";", "?", "," — those aren't commands
            if (!extra.isEmpty()) {
                // ONE finding per phase: previously each probe ('/', '/bukkit:', '/paper:' ...)
                // produced a separate HIGH — the same leak inflated the summary (10 of 16 HIGHs in
                // one test).
                List<String> ev = new ArrayList<>();
                ev.add("probe '" + probe.trim() + "' (+" + extra.size() + " outside the tree)");
                for (String e : withFullListPointer(probe.trim(), extra)) {
                    if (ev.size() >= 8) break;
                    ev.add(e);
                }
                add(Severity.HIGH, "commands", "Commands outside the client tree are enumerated via tab-complete",
                    ev, REC_TABCOMPLETE);
            }
        }
    }

    /**
     * If the list is large (a finding's evidence is cut at 200), saves the FULL list as a separate
     * file and adds a pointer to it as the FIRST line — it is guaranteed to land within those 200
     * (the truncation will cut the long tail of the original items, not this mark).
     */
    private List<String> withFullListPointer(String label, List<String> items) {
        if (items.size() <= FULL_LIST_POINTER_THRESHOLD) return items;
        String path = s.reporter.saveFullList(label, items);
        if (path == null) return items;
        List<String> withPointer = new ArrayList<>(items.size() + 1);
        withPointer.add("[full list: " + items.size() + " items, untruncated — " + path + "]");
        withPointer.addAll(items);
        return withPointer;
    }

    /** The server sometimes answers tab-complete with pure garbage like ";", "?", "," , "" — not commands/names. */
    private static List<String> withoutGarbageTokens(List<String> items) {
        List<String> out = new ArrayList<>();
        for (String s : items) if (!looksLikeGarbageToken(s)) out.add(s);
        return out;
    }

    private static boolean looksLikeGarbageToken(String s) {
        String t = s.trim();
        if (t.isEmpty()) return true;
        for (int i = 0; i < t.length(); i++) if (Character.isLetterOrDigit(t.charAt(i))) return false;
        return true; // not a single letter/digit in the whole string
    }

    /**
     * true if ALL suggestions are names of players who are online right now (the client's tab list).
     * Then it is not a plugin/topic list but Bukkit tab-complete's standard "player argument"
     * fallback for an unregistered/unknown command (see the /icanhasbukkit case).
     */
    private boolean looksLikePlayerFallback(List<String> names) {
        if (names.isEmpty()) return false;
        Set<String> online = onlineNames();
        if (online.isEmpty()) return false;
        for (String n : names) if (!online.contains(n.toLowerCase())) return false;
        return true;
    }

    private void hiddenPlayers(String cmd, List<String> names) {
        Set<String> online = onlineNames();
        if (online.isEmpty()) return;
        List<String> extra = new ArrayList<>();
        for (String n : names) {
            if (n.startsWith("@")) continue;               // selectors (@a, @p, ...)
            if (!USERNAME.matcher(n).matches()) continue;   // "*", "**" and similar placeholders — not names
            if (!online.contains(n.toLowerCase())) extra.add(n);
        }
        if (!extra.isEmpty()) {
            addGrouped(Severity.HIGH, "players", "Hidden (vanish) players leak via tab-complete: %s", "/" + cmd,
                withFullListPointer("/" + cmd, extra),
                "Filter name completions by player visibility (canSee) — many forks/plugins do it themselves; check your vanish plugin's settings.");
        }
    }

    // ---------------------------------------------------------------- nearly identical large lists

    /**
     * The command REALLY IS in the tree (already verified), but the base probe "/cmd " returned
     * nothing — that looks like an active block. We try to BYPASS it with the same means available
     * to ordinary tab-complete (no command execution, still purely read-only):
     *  - a plausible 2nd argument (maybe the command has a "/cmd <plugin> ..." branch with its own suggestions);
     *  - a different case of the command name (maybe the block compares the buffer literally while
     *    Bukkit lower-cases command names during parsing — then the bypass works);
     *  - a double trailing space (same idea: a naive "exactly one space" check).
     * Mutations touching the command NAME itself or its beginning (a null byte, a space right after
     * "/") are deliberately not tried: a null byte risks the server dropping the connection while
     * reading the string, and a space after "/" is in practice cut before reaching the server
     * (verified by hand).
     */
    private void maybeDeepProbeOnEmpty(String cmd, String args) {
        if (!s.cfg.deepProbeOnEmpty) return;
        if (args == null || !args.isEmpty()) return; // only for the base "/cmd " form without arguments of its own
        if (!(VERSION_CMDS.contains(cmd) || PLUGIN_LISTERS.contains(cmd) || HELP_CMDS.contains(cmd))) return;
        if (!rootCommands.contains(cmd)) return; // the command doesn't exist at all — not a block, nothing to bypass
        synchronized (this) {
            if (!deepProbeAttempted.add(cmd)) return; // already tried for this command — don't loop
        }
        List<String> followups = buildDeepProbeFollowups(cmd, s.cfg.deepProbeTokens);
        synchronized (this) {
            deepProbeTexts.addAll(followups);
        }
        for (String f : followups) s.prober.enqueue(f);
    }

    /** A pure function (no Session) — which mutations are tried when the base "/cmd " is empty. Separate for testability. */
    static List<String> buildDeepProbeFollowups(String cmd, List<String> tokens) {
        String slash = "/" + cmd;
        List<String> followups = new ArrayList<>();
        for (String token : tokens) followups.add(slash + " " + token + " ");
        followups.add(slash.toUpperCase() + " ");
        followups.add(slash + "  ");
        // A space right after "/" — it may in theory be cut before reaching the server, or arrive as
        // a valid string and fail to match the Brigadier literal (who is right is unverified; we'll
        // learn from a live server). No risk: it is an ordinary valid string, not a protocol
        // violation, so we simply try it.
        followups.add("/ " + cmd + " ");
        // A trailing §r: an ordinary printable character (U+00A7 + 'r'), no different from a space or
        // case at the protocol level — also simply tried, in case of a naive "the buffer equals
        // exactly this string" check.
        // \n (line feed) is NOT added: unlike §, it is a control character, and there are reasons to
        // believe the same validation that cuts null bytes may cut it too — the same risk profile as
        // the null byte, with no more benefit than the already-added mutations.
        followups.add(slash + " \u00a7r");
        return followups;
    }

    /** Collect this phase's large suggestion lists to find near-identical groups at session close. */
    private synchronized void noteBigList(String probe, List<String> suggestions) {
        if (suggestions.size() < BIGLIST_MIN_SIZE) return;
        bigLists.computeIfAbsent(currentPhase, k -> new LinkedHashMap<>()).put(probe, new ArrayList<>(suggestions));
    }

    /** A live tab-list snapshot at probe processing time — accumulated because by finalize() (session
     * close) the connection may already be dead and getOnlinePlayers() would return nothing. */
    private synchronized void noteOnlineSnapshot(int phase, Set<String> online) {
        if (!online.isEmpty()) everOnlineByPhase.computeIfAbsent(phase, k -> new HashSet<>()).addAll(online);
    }

    /**
     * Main thread, called before building the report (Session.close). Looks for GROUPS of probes
     * with byte-identical lists (frequent aliases of one command — /ci, /clean, /clear, ...), then
     * looks for CONNECTED COMPONENTS among those groups by a similarity threshold — not just
     * adjacent pairs, otherwise 4 mutually similar groups give C(4,2)=6 copies of the same finding
     * instead of one.
     * <p>
     * If the component's common core is mostly names (a shared player-argument list used by lots of
     * commands like /msg, /tell, /mv, /ruda...), the differences between component members are
     * cross-checked against everyone ever seen in the tab list during the scan: someone who was
     * there NOT ONCE is a probable hidden/vanish player (HIGH), not just a "custom item" (MEDIUM).
     * Since a player may have joined/left right during the scan, a difference alone is not proof —
     * the cross-check against the overall tab snapshot removes most of those false positives.
     */
    synchronized void finalizeBigListDiffs() {
        for (Map.Entry<Integer, Map<String, List<String>>> byPhase : bigLists.entrySet()) {
            int phase = byPhase.getKey();
            List<Map.Entry<String, List<String>>> probes = new ArrayList<>(byPhase.getValue().entrySet());
            int n = probes.size();
            if (n < 2) continue;

            List<Set<String>> sets = new ArrayList<>();
            for (Map.Entry<String, List<String>> e : probes) sets.add(new LinkedHashSet<>(e.getValue()));

            // Step 1: group probes with BYTE-IDENTICAL lists — exact match, not a similarity
            // threshold, otherwise union-find's transitivity would merge everything right here.
            int[] parent = new int[n];
            for (int i = 0; i < n; i++) parent[i] = i;
            for (int i = 0; i < n; i++) {
                for (int j = i + 1; j < n; j++) {
                    if (sets.get(i).equals(sets.get(j))) union(parent, i, j);
                }
            }
            Map<Integer, List<Integer>> exactGroups = new LinkedHashMap<>();
            for (int i = 0; i < n; i++) exactGroups.computeIfAbsent(find(parent, i), k -> new ArrayList<>()).add(i);

            List<List<String>> labels = new ArrayList<>();
            List<Set<String>> reps = new ArrayList<>();
            for (List<Integer> members : exactGroups.values()) {
                List<String> lbl = new ArrayList<>();
                for (int idx : members) lbl.add(probes.get(idx).getKey().trim());
                labels.add(lbl);
                reps.add(sets.get(members.get(0))); // all group members are byte-identical — any representative works
            }
            int g = reps.size();

            // Step 2: now the GROUPS (not individual probes) are merged into connected components by
            // a similarity threshold — so several mutually similar groups become ONE component.
            int[] gparent = new int[g];
            for (int i = 0; i < g; i++) gparent[i] = i;
            for (int i = 0; i < g; i++) {
                for (int j = i + 1; j < g; j++) {
                    if (isNearDuplicate(reps.get(i), reps.get(j))) union(gparent, i, j);
                }
            }
            Map<Integer, List<Integer>> components = new LinkedHashMap<>();
            for (int i = 0; i < g; i++) components.computeIfAbsent(find(gparent, i), k -> new ArrayList<>()).add(i);

            Set<String> everOnline = everOnlineByPhase.getOrDefault(phase, Collections.<String>emptySet());
            for (List<Integer> memberIdx : components.values()) {
                reportBigListComponent(phase, memberIdx, labels, reps, everOnline);
            }
        }
    }

    private void reportBigListComponent(int phase, List<Integer> memberIdx, List<List<String>> labels,
                                         List<Set<String>> reps, Set<String> everOnline) {
        List<String> allLabels = new ArrayList<>();
        for (int idx : memberIdx) allLabels.addAll(labels.get(idx));
        int totalCommands = allLabels.size();

        if (memberIdx.size() == 1) {
            // It didn't group with anyone by similarity — but if MANY commands answer with the same
            // list at once, that is worth seeing by itself (usually one command's aliasing).
            if (totalCommands < BIGLIST_MIN_IDENTICAL_GROUP) return;
            add(phase, Severity.LOW, "commands",
                totalCommands + " commands answer with the same list (" + reps.get(memberIdx.get(0)).size() + " items)",
                Collections.singletonList("commands: " + joinCapped(allLabels, 15)),
                "Informational; probably ordinary aliasing of one command. If the list contains something "
                    + "sensitive (names, custom items) — it leaks through all the listed commands at once.");
            return;
        }

        // The core is the intersection of ALL component members; what a specific subgroup differs by is the interesting part.
        Set<String> core = null;
        for (int idx : memberIdx) {
            if (core == null) core = new LinkedHashSet<>(reps.get(idx));
            else core.retainAll(reps.get(idx));
        }
        boolean coreLooksLikeRoster = looksLikeRoster(core, everOnline);

        List<String> genericDiffs = new ArrayList<>();
        List<String> churnNotes = new ArrayList<>();
        List<String> hiddenCandidates = new ArrayList<>();
        boolean anyRealDiff = false;

        for (int idx : memberIdx) {
            Set<String> peculiar = new LinkedHashSet<>(reps.get(idx));
            peculiar.removeAll(core);
            peculiar.removeIf(x -> x.matches("\\*+")); // wildcard placeholders ("*", "**") — not content
            if (peculiar.isEmpty()) continue;
            String who = String.join(", ", labels.get(idx));
            for (String item : peculiar) {
                anyRealDiff = true;
                if (coreLooksLikeRoster && isUsernameShaped(item)) {
                    if (everOnline.contains(item.toLowerCase())) {
                        churnNotes.add(item + " — only in [" + who + "]; but was seen in the tab list at another "
                            + "moment of the scan, looks like an ordinary join/leave during the scan");
                    } else {
                        hiddenCandidates.add(item + " — only in [" + who + "]; NEVER seen in the tab list during the whole scan");
                    }
                } else {
                    genericDiffs.add("only in [" + who + "]: " + item);
                }
            }
        }

        if (!anyRealDiff) {
            if (totalCommands >= BIGLIST_MIN_IDENTICAL_GROUP) {
                add(phase, Severity.LOW, "commands",
                    totalCommands + " commands answer with nearly the same list (" + core.size() + " items)",
                    Collections.singletonList("commands: " + joinCapped(allLabels, 15)),
                    "Informational; looks like aliasing of one command or a shared argument list.");
            }
            return;
        }

        List<String> ev = new ArrayList<>();
        ev.add("commands in the group: " + totalCommands + " (" + joinCapped(allLabels, 12) + "), common core: " + core.size() + " items");
        ev.addAll(genericDiffs);
        ev.addAll(churnNotes);
        ev.addAll(hiddenCandidates);

        if (!hiddenCandidates.isEmpty()) {
            add(phase, Severity.HIGH, "players",
                "Hidden players are visible through a shared argument list of " + totalCommands + " commands",
                ev, "The player list tab-complete offers for these commands contains names that were NEVER in "
                    + "the visible tab list during the scan — that looks like a vanish/hidden-player leak. "
                    + "Filter completions by player visibility (canSee), not just the tab list itself.");
        } else if (!genericDiffs.isEmpty()) {
            add(phase, Severity.MEDIUM, "commands",
                totalCommands + " commands return nearly the same list — the differences are probably custom items",
                ev, "The difference between the commands is the interesting part: most likely custom items/values. "
                    + "The full common list by itself is not a secret.");
        }
        // if the only differences are churnNotes (ordinary churn without a real leak), no separate
        // finding is created: this is not about technical leaks but about natural online dynamics.
    }

    /**
     * Not only must the core TEXTUALLY look like names (letters+digits+underscore, 3-16 chars) —
     * ordinary technical ids like "item_42"/"custom_relic" also accidentally match that format. So
     * we additionally require a noticeable part of the core to actually appear in the live tab list
     * during the scan: for a real player list that's nearly 100% (it came FROM the tab list), while
     * an item/material registry has zero matches.
     */
    private static boolean looksLikeRoster(Set<String> core, Set<String> everOnline) {
        if (core.isEmpty() || everOnline.isEmpty() || !looksLikeUsernameSet(core)) return false;
        int overlap = 0;
        for (String s : core) if (everOnline.contains(s.toLowerCase())) overlap++;
        return (double) overlap / core.size() >= 0.5;
    }

    private static boolean looksLikeUsernameSet(Set<String> items) {
        if (items.isEmpty()) return false;
        int match = 0;
        for (String s : items) if (isUsernameShaped(s)) match++;
        return (double) match / items.size() >= 0.8;
    }

    private static boolean isUsernameShaped(String s) {
        return USERNAME.matcher(s).matches();
    }

    private static boolean isNearDuplicate(Set<String> a, Set<String> b) {
        int minSize = Math.min(a.size(), b.size());
        if (minSize == 0) return false;
        Set<String> common = new LinkedHashSet<>(a);
        common.retainAll(b);
        int diff = a.size() + b.size() - 2 * common.size();
        if (diff == 0 || diff > BIGLIST_MAX_DIFF) return false; // 0 = an exact duplicate (unreachable here by construction); too many = just different lists
        return (double) common.size() / minSize >= BIGLIST_MIN_OVERLAP;
    }

    private static String joinCapped(List<String> items, int max) {
        if (items.size() <= max) return String.join(", ", items);
        return String.join(", ", items.subList(0, max)) + ", ... " + (items.size() - max) + " more";
    }

    private static int find(int[] parent, int x) {
        while (parent[x] != x) {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        return x;
    }

    private static void union(int[] parent, int x, int y) {
        int rx = find(parent, x), ry = find(parent, y);
        if (rx != ry) parent[rx] = ry;
    }

    private Set<String> onlineNames() {
        Set<String> r = new HashSet<>();
        ClientPlayNetHandler h = Minecraft.getInstance().getConnection();
        if (h != null) {
            for (NetworkPlayerInfo i : h.getOnlinePlayers()) r.add(i.getProfile().getName().toLowerCase());
        }
        return r;
    }
}
