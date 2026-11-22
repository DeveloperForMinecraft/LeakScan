package dev.leakscan;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.minecraft.client.Minecraft;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * A server-list ping BEFORE login: a separate TCP connection to the SAME host the player connects
 * to (the address is taken from NetworkManager/ServerData, nothing to guess). Returns version.name,
 * players.sample, favicon (sha1) and Forge modinfo — all of it is reported by the server even
 * before login. Anti-bots may dislike the separate connection — disable with pingOnJoin=false.
 */
final class PingProbe {

    private PingProbe() {
    }

    static void run(Session s) {
        if (s.pingHost == null || s.pingHost.isEmpty()) return;
        Thread t = new Thread(() -> {
            try {
                String json = ping(s.pingHost, s.pingPort, s.cfg.pingTimeoutMs);
                if (json == null) return;
                deliver(s, json);
            } catch (Throwable e) {
                LeakScanMod.LOGGER.debug("ping probe failed for {}:{}", s.pingHost, s.pingPort, e);
            }
        }, "LeakScan-PingProbe");
        t.setDaemon(true);
        t.start();
    }

    private static void deliver(Session s, String rawJson) {
        try {
            JsonObject o = new Gson().fromJson(rawJson, JsonObject.class);
            String versionName = o.has("version") && o.get("version").isJsonObject()
                ? str(o.getAsJsonObject("version").get("name")) : null;
            int online = 0, max = 0;
            List<String> sample = new ArrayList<>();
            if (o.has("players") && o.get("players").isJsonObject()) {
                JsonObject pl = o.getAsJsonObject("players");
                online = pl.has("online") ? pl.get("online").getAsInt() : 0;
                max = pl.has("max") ? pl.get("max").getAsInt() : 0;
                if (pl.has("sample") && pl.get("sample").isJsonArray()) {
                    for (JsonElement e : pl.getAsJsonArray("sample")) {
                        String n = e.isJsonObject() ? str(e.getAsJsonObject().get("name")) : null;
                        if (n != null && !n.isEmpty()) sample.add(n);
                    }
                }
            }
            String faviconSha1 = null;
            if (o.has("favicon")) {
                String fav = str(o.get("favicon"));
                if (fav != null && fav.length() > 32) {
                    MessageDigest md = MessageDigest.getInstance("SHA-1");
                    byte[] hash = md.digest(fav.getBytes(StandardCharsets.UTF_8));
                    StringBuilder sb = new StringBuilder();
                    for (byte b : hash) sb.append(String.format("%02x", b));
                    faviconSha1 = sb.toString();
                }
            }
            List<String> forgeMods = new ArrayList<>();
            if (o.has("modinfo") && o.get("modinfo").isJsonObject()) {
                JsonObject mi = o.getAsJsonObject("modinfo");
                if (mi.has("modList") && mi.get("modList").isJsonArray()) {
                    for (JsonElement e : mi.getAsJsonArray("modList")) {
                        String id = e.isJsonObject() ? str(e.getAsJsonObject().get("modid")) : null;
                        if (id != null) forgeMods.add(id + (e.getAsJsonObject().has("version")
                            ? ":" + str(e.getAsJsonObject().get("version")) : ""));
                    }
                }
            }
            final String vName = versionName, fav = faviconSha1, raw = rawJson;
            final int on = online, mx = max;
            final List<String> smp = sample, mods = forgeMods;
            Minecraft.getInstance().execute(() -> s.analyzer.onPingResult(vName, on, mx, smp, fav, mods, raw));
        } catch (Throwable e) {
            LeakScanMod.LOGGER.debug("ping parse failed", e);
        }
    }

    private static String str(JsonElement e) {
        return e == null || e.isJsonNull() ? null : e.getAsString();
    }

    /** The status-ping handshake: Handshake(0x00) + Status Request(0x00), reading one framed response. */
    private static String ping(String host, int port, int timeoutMs) throws Exception {
        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(host, port), timeoutMs);
            sock.setSoTimeout(timeoutMs);
            OutputStream out = sock.getOutputStream();
            byte[] hostB = host.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream hs = new ByteArrayOutputStream();
            writeVarInt(hs, 754);            // protocol 1.16.5
            writeVarInt(hs, hostB.length);
            hs.write(hostB);
            hs.write((port >>> 8) & 0xFF);
            hs.write(port & 0xFF);
            writeVarInt(hs, 1);              // next state = Status
            ByteArrayOutputStream msg = new ByteArrayOutputStream();
            msg.write(0x00);                 // packet id Handshake
            msg.write(hs.toByteArray());
            writeFramed(out, msg.toByteArray());
            msg.reset();
            msg.write(0x00);                 // Status Request
            writeFramed(out, msg.toByteArray());
            out.flush();

            InputStream in = sock.getInputStream();
            int len = readVarInt(in);
            ByteArrayOutputStream resp = new ByteArrayOutputStream();
            for (int i = 0; i < len; i++) {
                int b = in.read();
                if (b < 0) break;
                resp.write(b);
            }
            byte[] data = resp.toByteArray();
            // the response: [packet id varint][json string]
            int[] pos = {0};
            int packetId = nextVarInt(data, pos);
            if (packetId != 0x00) return null;
            int jsonLen = nextVarInt(data, pos);
            if (jsonLen < 0 || pos[0] + jsonLen > data.length) return null;
            return new String(data, pos[0], jsonLen, StandardCharsets.UTF_8);
        }
    }

    private static void writeFramed(OutputStream out, byte[] payload) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writeVarInt(buf, payload.length);
        buf.write(payload);
        out.write(buf.toByteArray());
    }

    private static void writeVarInt(ByteArrayOutputStream out, int value) {
        do {
            byte b = (byte) (value & 0x7F);
            value >>>= 7;
            if (value != 0) b |= (byte) 0x80;
            out.write(b);
        } while (value != 0);
    }

    private static int readVarInt(InputStream in) throws Exception {
        int result = 0, shift = 0, b;
        do {
            b = in.read();
            if (b < 0) return -1;
            result |= (b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        return result;
    }

    private static int nextVarInt(byte[] data, int[] pos) {
        int result = 0, shift = 0;
        while (pos[0] < data.length) {
            byte b = data[pos[0]++];
            result |= (b & 0x7F) << shift;
            shift += 7;
            if ((b & 0x80) == 0) break;
        }
        return result;
    }
}
