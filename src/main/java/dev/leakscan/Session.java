package dev.leakscan;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.suggestion.Suggestion;
import com.mojang.brigadier.suggestion.Suggestions;
import com.mojang.brigadier.tree.RootCommandNode;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.local.LocalChannel;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.network.NetworkManager;
import net.minecraft.util.ResourceLocation;
import net.minecraft.util.text.ITextComponent;
import net.minecraft.util.text.StringTextComponent;

import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** One connection = one session = one folder of logs/report. */
final class Session {
    static volatile Session current;

    final Config cfg = Config.get();
    final NetworkManager nm;
    final Path dir;
    final long startMs = System.currentTimeMillis();
    final Reporter reporter;
    final Analyzer analyzer;
    final Prober prober;
    final Map<String, AtomicInteger> histogram = new ConcurrentHashMap<>();

    final PhaseDetector phaseDetector = new PhaseDetector();
    final String hostKey;
    final String pingHost;
    final int pingPort;
    final Path channelDbPath;
    final ChannelDb channelDb; // null if channelPatternAnalysis=false in the config
    final ResourcePackFingerprintDb rpFingerprintDb; // null if resourcePackFingerprintDb=false

    volatile long loggedInAt;
    volatile int loginCount;
    volatile boolean sawJoin, sawCommandList, closed;
    private boolean handlerScanned;

    // Pre-login ping result (the same host as the connection; a separate socket, see PingProbe).
    volatile String pingVersionName, pingFaviconSha1;
    volatile List<String> pingSampleNames = java.util.Collections.emptyList();

    // ------------------------------------------------------------ lifecycle

    static synchronized Session attach(NetworkManager nm) {
        Session cur = current;
        if (cur != null && cur.nm == nm) return cur;
        if (cur != null) cur.close();
        if (nm.channel() == null || nm.channel() instanceof LocalChannel) return null; // singleplayer is not interesting
        Session s = new Session(nm);
        current = s;
        try {
            ChannelPipeline p = nm.channel().pipeline();
            if (p.get(PacketSniffer.NAME) != null) p.remove(PacketSniffer.NAME);
            p.addBefore("packet_handler", PacketSniffer.NAME, new PacketSniffer(s));
        } catch (Exception e) {
            LeakScanMod.LOGGER.error("cannot install packet sniffer", e);
        }
        if (s.cfg.pingOnJoin) PingProbe.run(s);
        return s;
    }

    static synchronized void detach() {
        Session c = current;
        current = null;
        if (c != null) c.close();
    }

    private Session(NetworkManager nm) {
        this.nm = nm;
        this.hostKey = hostKey(nm);
        String[] hp = hostPortForPing(nm);
        this.pingHost = hp[0];
        this.pingPort = Integer.parseInt(hp[1]);
        String ts = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
        this.dir = Config.dir().resolve("sessions").resolve(hostKey + "_" + ts);
        this.reporter = new Reporter(dir);
        this.analyzer = new Analyzer(this);
        this.prober = new Prober(this);
        this.channelDbPath = Config.dir().resolve("channel-db").resolve(hostKey + ".json");
        this.channelDb = cfg.channelPatternAnalysis ? ChannelPatternAnalyzer.load(channelDbPath) : null;
        this.rpFingerprintDb = cfg.resourcePackFingerprintDb ? ResourcePackFingerprintDb.load() : null;
        loadExternalCommands();
    }

    private static String hostKey(NetworkManager nm) {
        String h = null;
        try {
            ServerData sd = Minecraft.getInstance().getCurrentServer();
            if (sd != null) h = sd.ip;
        } catch (Throwable ignored) {
        }
        if (h == null || h.isEmpty()) {
            SocketAddress a = nm.channel().remoteAddress();
            h = a == null ? "server" : a.toString();
        }
        return h.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    /** host+port for the pre-login ping: the same address the player actually connects to. */
    private static String[] hostPortForPing(NetworkManager nm) {
        try {
            ServerData sd = Minecraft.getInstance().getCurrentServer();
            if (sd != null && sd.ip != null && !sd.ip.isEmpty()) {
                String ip = sd.ip;
                int b = ip.lastIndexOf('/');
                if (b >= 0) ip = ip.substring(b + 1); // no "user@host" forms expected, but stripping doesn't hurt
                int c = ip.lastIndexOf(':');
                if (c > 0 && ip.indexOf(':') == c) { // exactly one ':' — host:port, NOT IPv6
                    return new String[]{ip.substring(0, c), ip.substring(c + 1)};
                }
                return new String[]{ip, "25565"};
            }
        } catch (Throwable ignored) {
        }
        try {
            java.net.InetSocketAddress a = (java.net.InetSocketAddress) nm.channel().remoteAddress();
            if (a != null) return new String[]{a.getHostString(), String.valueOf(a.getPort())};
        } catch (Throwable ignored) {
        }
        return new String[]{"", "25565"};
    }

    /** Commands collected by your other mod: one per line (may include '/' and arguments). */
    private void loadExternalCommands() {
        if (cfg.externalCommandsFile == null || cfg.externalCommandsFile.isEmpty()) return;
        List<String> names = new ArrayList<>();
        try {
            for (String line : Files.readAllLines(java.nio.file.Paths.get(cfg.externalCommandsFile), StandardCharsets.UTF_8)) {
                String c = line.trim().toLowerCase();
                if (c.startsWith("/")) c = c.substring(1);
                int sp = c.indexOf(' ');
                if (sp > 0) c = c.substring(0, sp);
                if (!c.isEmpty()) names.add(c);
            }
            analyzer.addExternalCommands(names);
        } catch (Exception e) {
            LeakScanMod.LOGGER.warn("cannot read externalCommandsFile", e);
        }
    }

    synchronized void close() {
        if (closed) return;
        closed = true;
        try {
            nm.channel().pipeline().remove(PacketSniffer.NAME);
        } catch (Exception ignored) {
        }
        analyzer.finalizeBigListDiffs();
        analyzer.finalizeChannelFindings();
        analyzer.finalizeVanishTripleDiff();
        if (channelDb != null) ChannelPatternAnalyzer.save(channelDbPath, channelDb);
        if (cfg.globalChannelIndex) GlobalChannelIndex.mergeSession(channelDb, hostKey);
        reporter.writeReport(this);
        reporter.close();
    }

    /**
     * Main thread: Forge fires this on first entry into a world. We do NOT rely on it for backend
     * switches behind Velocity/BungeeCord — the TCP connection is the same there and this event
     * does not fire a second time; environment changes are caught by PhaseDetector from packets
     * (see onPhaseChange).
     */
    void onLoggedIn() {
        loginCount++;
        loggedInAt = System.currentTimeMillis();
        handlerScanned = false;
        try {
            if (Minecraft.getInstance().player != null) {
                analyzer.ownUuid = Minecraft.getInstance().player.getUUID();
            }
        } catch (Throwable ignored) {
        }
        prober.onLogin();
        notifyUser("\u00a7aactive. Logs: " + dir.getFileName() + "  (.ls help)");
    }

    /** Main thread, every tick. */
    void tick() {
        if (closed || loggedInAt == 0) return;
        long now = System.currentTimeMillis();
        if (!handlerScanned && now - loggedInAt > 1500) {
            handlerScanned = true;
            scanPlayHandler();
        }
        if (now - loggedInAt < cfg.startDelayMs) return;
        prober.tick(now);
    }

    /**
     * A safety net: some early play packets (JoinGame, brand, the command tree) may arrive before
     * the sniffer is installed. We pull the same data from the ClientPlayNetHandler state.
     */
    private void scanPlayHandler() {
        try {
            Object h = Minecraft.getInstance().getConnection();
            if (h == null) return;
            if (!sawJoin) {
                for (Set<?> set : Refl.all(h, Set.class)) collectWorlds(set);
            }
            if (analyzer.rootCommands.isEmpty() || !sawCommandList) {
                Object d = Refl.get(h, CommandDispatcher.class);
                if (d != null) analyzer.onCommandTree(((CommandDispatcher<?>) d).getRoot());
            }
        } catch (Throwable t) {
            LeakScanMod.LOGGER.warn("scanPlayHandler failed", t);
        }
    }

    // ------------------------------------------------------------ chat output

    void say(String msg) {
        Minecraft mc = Minecraft.getInstance();
        mc.execute(() -> {
            if (mc.player != null) {
                mc.player.sendMessage(new StringTextComponent("\u00a7b[LeakScan]\u00a7r " + msg), new UUID(0L, 0L));
            }
        });
    }

    /** Automatic notifications (not replies to .ls commands): suppressed in silentMode. */
    void notifyUser(String msg) {
        if (!cfg.silentMode) say(msg);
    }

    void alert(Severity sev, String title) {
        if (cfg.notifyInChat && !cfg.silentMode) say("\u00a7c" + sev + "\u00a7r " + title);
    }

    // ------------------------------------------------------------ packet hooks (Netty thread)

    boolean onInbound(Object msg) {
        String cn = Refl.classNameOf(msg); // cached getSimpleName: no allocation per packet
        histogram.computeIfAbsent(cn, k -> new AtomicInteger()).incrementAndGet();

        long now = System.currentTimeMillis();
        List<String> triggers = phaseDetector.note(cn, now);
        if (triggers != null) onPhaseChange(triggers, now);

        switch (cn) {
            case "SCustomPayloadPlayPacket": onPayload(msg); return false;
            case "SCommandListPacket": onCommandList(msg); return false;
            case "STabCompletePacket": return onTabComplete(msg);
            case "SJoinGamePacket": onJoin(msg); return false;
            case "SSendResourcePackPacket": onResourcePack(msg); return false;
            case "SPlayerListHeaderFooterPacket": onHeaderFooter(msg, now); return false;
            case "SChatPacket": onChat(msg); return false;
            case "SDisconnectPacket": onDisconnect(msg); return false;
            case "STeamsPacket": onTeams(msg); return false;
            case "SPlaySoundPacket": onSoundResource(msg); return false;
            case "SKeepAlivePacket": onKeepAlive(now); return false;
            case "SUpdateBossInfoPacket": onBossBar(msg); return false;
            case "SScoreboardObjectivePacket": onScoreboardObjective(msg); return false;
            case "SPlayerListItemPacket": onPlayerListItem(msg); return false;
            case "SSpawnPlayerPacket": onSpawnPlayer(msg); return false;
            case "SUpdateTimePacket": onTimeUpdate(msg, now); return false;
            case "SUpdateScorePacket": onScoreUpdate(now); return false;
            case "SUpdateHealthPacket": onHealth(msg, now); return false;
            case "SCustomPayloadLoginPacket": onLoginPayload(msg); return false;
            case "SDisconnectLoginPacket": onLoginDisconnect(msg); return false;
            case "SEnableCompressionPacket": reporter.packet("S_COMPRESSION", ByteUtil.kv("ints", Refl.ints(msg))); return false;
            default: return false; // noise (chunks, entities, recipes, advancements, ...) — counter only
        }
    }

    /** Netty thread: the environment apparently changed (another backend behind a proxy, another limbo, ...). */
    void onPhaseChange(List<String> triggers, long now) {
        int phase = phaseDetector.phase();
        analyzer.beginPhase(phase, now, triggers);
        prober.reset();
        prober.onLogin();
        reporter.packet("PHASE_CHANGE", ByteUtil.kv("phase", phase, "triggers", triggers));
        notifyUser("\u00a7ethe environment apparently changed (phase " + phase + "): " + String.join(", ", triggers)
            + ". Findings from now on go to a separate report section.");
    }

    void onOutbound(Object msg) {
        String cn = Refl.classNameOf(msg);
        histogram.computeIfAbsent("OUT:" + cn, k -> new AtomicInteger()).incrementAndGet();
        // Outbound plugin messages carry data too: an LP proxy delivers someone else's permission
        // updates TO a backend over an arbitrary player's connection (client->server, the
        // luckperms:update channel) — the vanilla client discards them silently, we log and scan.
        if (cn.equals("CCustomPayloadPacket")) {
            try {
                ResourceLocation id = Refl.get(msg, ResourceLocation.class);
                io.netty.buffer.ByteBuf buf = Refl.get(msg, io.netty.buffer.ByteBuf.class);
                if (id == null || buf == null) return;
                String ch = id.toString();
                if (ch.equalsIgnoreCase("minecraft:register") || ch.equalsIgnoreCase("minecraft:unregister")) return;
                int len = buf.readableBytes();
                byte[] data = ByteBufUtil.getBytes(buf, buf.readerIndex(), Math.min(len, 65536));
                reporter.packet("C_CUSTOM_PAYLOAD", ByteUtil.kv("channel", ch, "len", len,
                    "text", ByteUtil.preview(data, 300)));
                if (ch.toLowerCase().startsWith("luckperms:")) {
                    analyzer.scanText("outbound " + ch, ByteUtil.runs(data, 512));
                }
            } catch (Throwable ignored) {
            }
        }
    }

    private void onPayload(Object msg) {
        ResourceLocation id = Refl.get(msg, ResourceLocation.class);
        ByteBuf buf = Refl.get(msg, ByteBuf.class);
        if (id == null || buf == null) return;
        int len = buf.readableBytes();
        // Read without shifting the readerIndex: the packet will still be processed by the vanilla client.
        byte[] data = ByteBufUtil.getBytes(buf, buf.readerIndex(), Math.min(len, 65536));
        String ch = id.toString();
        // Log preview: first try an honest VarInt+UTF-8 parse (how minecraft:brand and many other
        // string channels are actually built), with protection against degenerate cases (see
        // ByteUtil.preview) — otherwise, for a genuinely binary channel, the first byte could
        // accidentally parse as len=0 or produce garbage.
        reporter.packet("S_CUSTOM_PAYLOAD", ByteUtil.kv("channel", ch, "len", len,
            "text", ByteUtil.preview(data, 300), "hex", ByteUtil.hex(data, 64)));
        analyzer.onChannel(ch, data);
        // minecraft:register/unregister is a service list of channel names, not a specific plugin's
        // payload; it is already parsed line by line via analyzer.onChannel/noteChannel — putting it
        // here as the "payload" of the "minecraft:register" channel only confuses (see the user report).
        String lc = ch.toLowerCase();
        boolean bookkeeping = lc.equals("minecraft:register") || lc.equals("register")
            || lc.equals("minecraft:unregister") || lc.equals("unregister");
        if (channelDb != null && !bookkeeping) {
            ChannelPatternAnalyzer.record(channelDb, ch, data, cfg.channelDbSampleBytes, cfg.channelDbMaxSamplesPerChannel);
        }
    }

    private void onCommandList(Object msg) {
        sawCommandList = true;
        RootCommandNode<?> root = Refl.get(msg, RootCommandNode.class);
        if (root != null) analyzer.onCommandTree(root);
        reporter.packet("S_COMMAND_LIST", ByteUtil.kv("rootCommands", analyzer.rootCommands.size()));
    }

    private boolean onTabComplete(Object msg) {
        List<Integer> ints = Refl.ints(msg);
        Suggestions sug = Refl.get(msg, Suggestions.class);
        if (sug == null) return false;
        List<String> texts = new ArrayList<>();
        List<String> tips = new ArrayList<>();
        for (Suggestion x : sug.getList()) {
            texts.add(x.getText());
            tips.add(x.getTooltip() != null ? x.getTooltip().getString() : null);
        }
        if (!ints.isEmpty() && ints.get(0) >= Prober.BASE) {
            prober.onResponse(ints.get(0), texts, tips);
            return true; // our answer — not handed to the vanilla client
        }
        // The player's own ordinary tab-complete: passive parsing.
        reporter.packet("S_TAB_COMPLETE", ByteUtil.kv("count", texts.size(), "suggestions", ByteUtil.cap(texts, 100)));
        for (String t : ByteUtil.cap(texts, 100)) analyzer.scanText("tab-complete (organic)", t);
        return false;
    }

    private void onJoin(Object msg) {
        sawJoin = true;
        List<String> worlds = new ArrayList<>();
        for (Set<?> set : Refl.all(msg, Set.class)) worlds.addAll(worldKeys(set));
        // int field order: entityId, maxPlayers, viewDistance (best-effort).
        List<Integer> ints = Refl.ints(msg);
        reporter.packet("S_JOIN_GAME", ByteUtil.kv("ints", ints, "worlds", worlds));
        analyzer.onWorlds(worlds);
        analyzer.onJoinInts(ints);
        if (cfg.scanDimensionCodec) {
            // In 1.16.5 JoinGame does NOT carry CompoundNBT fields (verified against the decompiled
            // packet): the dimension codec is decoded into objects — DynamicRegistries.Impl, which
            // holds a Map of registries (biomes, dimension types, ...), each registry holding a
            // BiMap<RegistryKey, value>. We walk field types (runtime names are SRG); the
            // RegistryKey.toString() keys give "ResourceKey[minecraft:worldgen/biome /
            // namespace:name]" — a foreign namespace is visible as is.
            Object dr = Refl.get(msg, net.minecraft.util.registry.DynamicRegistries.Impl.class);
            if (dr == null) dr = Refl.get(msg, net.minecraft.util.registry.DynamicRegistries.class);
            if (dr != null) {
                List<String> keys = new ArrayList<>();
                collectRegistryKeys(dr, keys);
                if (!keys.isEmpty()) analyzer.onDimensionCodec(keys);
            }
        }
    }

    private void onTeams(Object msg) {
        if (!cfg.scanTeamPackets) return;
        List<String> names = new ArrayList<>();
        for (java.util.Collection<?> c : Refl.all(msg, java.util.Collection.class)) {
            for (Object o : c) if (o instanceof String) names.add((String) o);
        }
        List<String> strs = Refl.all(msg, String.class); // the first string is usually the team's own name
        String teamName = strs.isEmpty() ? null : strs.get(0);
        if (names.isEmpty() && teamName == null) return;
        reporter.packet("S_TEAMS", ByteUtil.kv("team", teamName, "names", names));
        analyzer.onTeamPacket(teamName, names);
    }

    private void onSoundResource(Object msg) {
        if (!cfg.scanSoundNamespace) return;
        ResourceLocation id = Refl.get(msg, ResourceLocation.class);
        if (id == null) return;
        analyzer.onSoundResource(id.toString());
    }

    private void onKeepAlive(long now) {
        if (!cfg.scanKeepAliveTiming) return;
        analyzer.onKeepAlive(now);
    }

    private void onBossBar(Object msg) {
        if (!cfg.scanBossBar) return;
        ITextComponent name = Refl.get(msg, ITextComponent.class);
        if (name == null) return;
        String text = name.getString();
        reporter.packet("S_BOSS_BAR", ByteUtil.kv("text", text));
        analyzer.scanText("bossbar", text);
    }

    private void onScoreboardObjective(Object msg) {
        if (!cfg.scanScoreboardObjectives) return;
        List<String> strs = Refl.all(msg, String.class);
        String name = strs.isEmpty() ? null : strs.get(0);
        ITextComponent display = Refl.get(msg, ITextComponent.class);
        reporter.packet("S_SCOREBOARD_OBJECTIVE", ByteUtil.kv("name", name, "display", display == null ? null : display.getString()));
        if (name != null) analyzer.onScoreboardObjective(name);
        if (display != null) analyzer.scanText("scoreboard objective display", display.getString());
    }

    /** For the vanish triple diff: PlayerInfo ADD/REMOVE/UPDATE_LATENCY <-> entity spawn <-> chat join/leave. */
    private void onPlayerListItem(Object msg) {
        if (!cfg.vanishTripleDiff) return;
        Enum<?> action = Refl.get(msg, Enum.class);
        String actionName = action == null ? "" : action.name();
        boolean isAdd = actionName.contains("ADD");
        boolean isRemove = actionName.contains("REMOVE");
        boolean isLatency = actionName.equals("UPDATE_LATENCY");
        if (!isAdd && !isRemove && !isLatency) return; // UPDATE_GAME_MODE/UPDATE_DISPLAY_NAME — not our case

        List<UUID> uuids = new ArrayList<>();
        Map<UUID, String> names = new java.util.HashMap<>();
        for (java.util.Collection<?> c : Refl.all(msg, java.util.Collection.class)) {
            for (Object entry : c) {
                // The list elements are SPlayerListItemPacket.AddPlayerData: in 1.16.5 it has NO UUID
                // field — the uuid lives inside the GameProfile (verified against the decompiled
                // class). Searching for a UUID field directly always returned null, and the whole
                // PlayerInfo branch of the triple diff stayed silent.
                UUID id;
                com.mojang.authlib.GameProfile gp = entry instanceof com.mojang.authlib.GameProfile
                    ? (com.mojang.authlib.GameProfile) entry : Refl.get(entry, com.mojang.authlib.GameProfile.class);
                if (entry instanceof UUID) {
                    id = (UUID) entry;
                } else if (gp != null) {
                    id = gp.getId();
                } else {
                    id = Refl.get(entry, UUID.class);
                }
                if (id == null) continue;
                uuids.add(id);
                if (gp != null && gp.getName() != null) names.put(id, gp.getName());
            }
        }
        if (uuids.isEmpty()) return;
        if (isLatency) {
            // Hidden players keep receiving ping updates: vanish plugins often hide the tab list
            // but forget to filter UPDATE_LATENCY. Only "suspicious" ones are logged — analysis in Analyzer.
            reporter.packet("S_PLAYER_LIST_ITEM_LATENCY", ByteUtil.kv("uuids", uuids));
            analyzer.onPlayerInfoLatency(uuids);
        } else {
            reporter.packet("S_PLAYER_LIST_ITEM", ByteUtil.kv("action", actionName, "uuids", uuids));
            if (isAdd) analyzer.onPlayerInfoAdd(uuids, names);
            else analyzer.onPlayerInfoRemove(uuids);
        }
    }

    private void onSpawnPlayer(Object msg) {
        if (!cfg.vanishTripleDiff) return;
        UUID id = Refl.get(msg, UUID.class);
        if (id == null) return;
        reporter.packet("S_SPAWN_PLAYER", ByteUtil.kv("uuid", id.toString()));
        analyzer.onEntitySpawn(id);
    }

    private long lastTimeUpdateMs, lastWorldAge = Long.MIN_VALUE;

    private void onTimeUpdate(Object msg, long now) {
        if (!cfg.scanTpsFromTimeUpdate) return;
        List<Long> longs = Refl.longs(msg);
        if (longs.isEmpty()) return;
        long worldAge = longs.get(0); // the first long field is the world's game age (ticks since creation)
        if (lastWorldAge != Long.MIN_VALUE && lastTimeUpdateMs != 0) {
            long realMs = now - lastTimeUpdateMs;
            long tickDelta = worldAge - lastWorldAge;
            if (realMs > 0 && tickDelta >= 0 && realMs < 60_000) {
                double tps = tickDelta * 1000.0 / realMs;
                analyzer.onTpsSample(Math.min(tps, 20.5));
            }
        }
        lastTimeUpdateMs = now;
        lastWorldAge = worldAge;
    }

    private void collectWorlds(Set<?> set) {
        List<String> w = worldKeys(set);
        if (!w.isEmpty()) {
            reporter.packet("PLAY_HANDLER_WORLDS", ByteUtil.kv("worlds", w));
            analyzer.onWorlds(w);
        }
    }

    /** RegistryKey.toString() == "ResourceKey[minecraft:dimension / minecraft:overworld]" — mapping-independent. */
    private static List<String> worldKeys(Set<?> set) {
        List<String> out = new ArrayList<>();
        for (Object o : set) {
            String str = String.valueOf(o);
            if (!str.startsWith("ResourceKey[")) continue;
            int i = str.lastIndexOf(" / ");
            if (i > 0 && str.endsWith("]")) out.add(str.substring(i + 3, str.length() - 1));
        }
        return out;
    }

    /**
     * Recursively (2 levels: DynamicRegistries.Impl -> registries -> their keys) collects the
     * toString() of all keys of all dimension-codec registries. Works by field types (Map), no
     * method/field names touched.
     */
    private static void collectRegistryKeys(Object registriesHolder, List<String> out) {
        for (Map<?, ?> regMap : Refl.all(registriesHolder, Map.class)) {
            for (Object registry : regMap.values()) {
                if (registry == null || registry == registriesHolder) continue;
                for (Map<?, ?> inner : Refl.all(registry, Map.class)) {
                    for (Object k : inner.keySet()) {
                        if (k == null) continue;
                        String s = String.valueOf(k);
                        if (s.startsWith("ResourceKey[")) out.add(s);
                    }
                }
            }
        }
    }

    private void onResourcePack(Object msg) {
        List<String> strs = Refl.all(msg, String.class);
        String url = strs.size() > 0 ? strs.get(0) : "";
        String hash = strs.size() > 1 ? strs.get(1) : "";
        reporter.packet("S_RESOURCE_PACK", ByteUtil.kv("url", url, "hash", hash));
        analyzer.onResourcePack(url, hash);
    }

    private void onHeaderFooter(Object msg, long now) {
        List<String> texts = new ArrayList<>();
        for (ITextComponent c : Refl.all(msg, ITextComponent.class)) texts.add(c.getString());
        reporter.packet("S_TAB_HEADER_FOOTER", ByteUtil.kv("texts", texts));
        for (String t : texts) analyzer.scanText("tab header/footer", t);
        analyzer.onHeaderFooterPacket(now);
    }

    private void onScoreUpdate(long now) {
        analyzer.onScoreUpdatePacket(now);
    }

    /** Player death (health=0) — needed by PhaseDetector so a respawn is not confused with a server switch. */
    private void onHealth(Object msg, long now) {
        try {
            List<Float> fs = Refl.floats(msg);
            if (!fs.isEmpty() && fs.get(0) <= 0f) phaseDetector.noteDeath(now);
        } catch (Throwable ignored) {
        }
    }

    /**
     * Login phase (before JoinGame): the Forge handshake happens here. SCustomPayloadLoginPacket
     * carries the fml:handshake channel with the FULL server mod list (S2CModList), and proxies
     * carry their own channels (bungeecord:main etc.). Previously these packets only hit the histogram.
     */
    private void onLoginPayload(Object msg) {
        ResourceLocation id = Refl.get(msg, ResourceLocation.class);
        ByteBuf buf = Refl.get(msg, ByteBuf.class);
        if (id == null || buf == null) return;
        int len = buf.readableBytes();
        byte[] data = ByteBufUtil.getBytes(buf, buf.readerIndex(), Math.min(len, 65536));
        String ch = id.toString();
        reporter.packet("S_LOGIN_PAYLOAD", ByteUtil.kv("channel", ch, "len", len,
            "text", ByteUtil.preview(data, 300), "hex", ByteUtil.hex(data, 64)));
        analyzer.onLoginChannel(ch, data);
    }

    private void onLoginDisconnect(Object msg) {
        ITextComponent c = Refl.get(msg, ITextComponent.class);
        if (c == null) return;
        String t = c.getString();
        reporter.packet("S_LOGIN_DISCONNECT", ByteUtil.kv("reason", t));
        analyzer.scanText("login kick", t);
    }

    private static final java.util.regex.Pattern JOIN_MSG = java.util.regex.Pattern.compile("^(\\S+) joined the game$");
    private static final java.util.regex.Pattern LEAVE_MSG = java.util.regex.Pattern.compile("^(\\S+) left the game$");

    private void onChat(Object msg) {
        Enum<?> type = Refl.get(msg, Enum.class);
        if (type != null && type.name().equals("CHAT")) return; // player chat is not touched
        ITextComponent c = Refl.get(msg, ITextComponent.class);
        if (c == null) return;
        String t = c.getString();
        UUID sender = cfg.scanChatSenderUuid ? Refl.get(msg, UUID.class) : null;
        reporter.packet("S_SYSTEM_MESSAGE", ByteUtil.kv("type", type == null ? "?" : type.name(), "text", t,
            "senderUuid", sender == null ? null : sender.toString()));
        analyzer.onChatText(t);
        if (sender != null && !sender.equals(new UUID(0, 0))) {
            analyzer.onSystemMessageWithSender(t, sender);
        }
        if (cfg.vanishTripleDiff) {
            java.util.regex.Matcher jm = JOIN_MSG.matcher(t);
            if (jm.matches()) analyzer.onChatJoin(jm.group(1));
            java.util.regex.Matcher lm = LEAVE_MSG.matcher(t);
            if (lm.matches()) analyzer.onChatLeave(lm.group(1));
        }
    }

    private void onDisconnect(Object msg) {
        ITextComponent c = Refl.get(msg, ITextComponent.class);
        if (c == null) return;
        String t = c.getString();
        reporter.packet("S_DISCONNECT", ByteUtil.kv("reason", t));
        analyzer.scanText("kick message", t);
    }
}
