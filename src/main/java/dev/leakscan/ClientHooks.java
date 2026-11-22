package dev.leakscan;

import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screen.ConnectingScreen;
import net.minecraft.network.NetworkManager;
import net.minecraftforge.client.event.ClientChatEvent;
import net.minecraftforge.common.MinecraftForge;
import net.minecraftforge.event.TickEvent;
import net.minecraftforge.eventbus.api.SubscribeEvent;
import net.minecraftforge.client.event.ClientPlayerNetworkEvent;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Client events: sniffer installation, prober ticks, ".ls ..." chat commands. */
public final class ClientHooks {

    public static void init() {
        MinecraftForge.EVENT_BUS.register(new ClientHooks());
    }

    @SubscribeEvent
    public void onLoggedIn(ClientPlayerNetworkEvent.LoggedInEvent e) {
        NetworkManager nm = e.getNetworkManager();
        if (nm == null) return;
        Session s = Session.attach(nm); // no-op if already installed at the connecting screen
        if (s != null) s.onLoggedIn();
    }

    @SubscribeEvent
    public void onLoggedOut(ClientPlayerNetworkEvent.LoggedOutEvent e) {
        Session.detach();
    }

    @SubscribeEvent
    public void onTick(TickEvent.ClientTickEvent e) {
        if (e.phase != TickEvent.Phase.END) return;
        Minecraft mc = Minecraft.getInstance();

        // Early hook: while the connecting screen is up (login phase), install the sniffer so the
        // first play packets are not lost (JoinGame / brand / the command tree arrive right after LoginSuccess).
        if (mc.screen instanceof ConnectingScreen) {
            NetworkManager nm = Refl.get(mc.screen, NetworkManager.class);
            if (nm != null) Session.attach(nm);
        }

        Session s = Session.current;
        if (s == null) return;
        if (s.nm.channel() != null && !s.nm.channel().isActive()) {
            Session.detach();
            return;
        }
        s.tick();
    }

    @SubscribeEvent
    public void onChat(ClientChatEvent e) {
        String m = e.getMessage();
        if (m == null || !(m.equals(".ls") || m.startsWith(".ls "))) return;
        e.setCanceled(true);
        Session s = Session.current;
        if (s == null) return;

        String rest = m.length() > 4 ? m.substring(4) : "";
        String sub = rest, arg = "";
        int i = rest.indexOf(' ');
        if (i >= 0) {
            sub = rest.substring(0, i);
            arg = rest.substring(i + 1);
        }

        switch (sub.toLowerCase()) {
            case "status": {
                int total = 0;
                for (Map.Entry<String, AtomicInteger> en : s.histogram.entrySet()) total += en.getValue().get();
                int high = 0;
                for (Finding f : s.analyzer.snapshot()) if (f.severity.ordinal() >= Severity.HIGH.ordinal()) high++;
                s.say("phases/servers: " + s.analyzer.phases.size() + " (current: " + s.analyzer.currentPhase + "), packets: " + total
                    + ", findings: " + s.analyzer.snapshot().size() + " (HIGH+: " + high + "), probes: "
                    + s.prober.sent() + ", queued: " + s.prober.queued());
                break;
            }
            case "report":
                s.reporter.writeReport(s);
                s.say("report: " + s.reporter.dir().resolve("report.md"));
                break;
            case "label":
                s.cfg.label = arg.trim().isEmpty() ? s.cfg.label : arg.trim();
                s.say("profile: " + s.cfg.label);
                break;
            case "probe":
                probe(s, arg);
                break;
            default:
                s.say(".ls status | report | label <profile name>");
                s.say(".ls probe defaults | roots | <probe text>  ('~' = space, e.g.  .ls probe /msg~ )");
        }
    }

    private static void probe(Session s, String arg) {
        int n = 0;
        if (arg.equals("defaults")) {
            for (String p : Config.defaultProbes()) if (s.prober.enqueueManual(p)) n++;
        } else if (arg.equals("roots")) {
            synchronized (s.analyzer.rootCommands) {
                for (String r : s.analyzer.rootCommands) if (!r.contains(":") && s.prober.enqueueManual("/" + r + " ")) n++;
            }
        } else if (arg.startsWith("/")) {
            if (s.prober.enqueueManual(arg.replace('~', ' '))) n++;
        } else {
            s.say("a probe must start with '/', or be defaults / roots");
            return;
        }
        s.say("probes queued: " + n);
    }
}
