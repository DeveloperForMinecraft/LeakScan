package dev.leakscan;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;

/** Sits in the pipeline between "decoder"/"encoder" and "packet_handler": sees fully parsed IPackets. */
final class PacketSniffer extends ChannelDuplexHandler {
    static final String NAME = "leakscan";
    private final Session session;

    PacketSniffer(Session session) {
        this.session = session;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        boolean consume = false;
        try {
            consume = session.onInbound(msg);
        } catch (Throwable t) {
            LeakScanMod.LOGGER.warn("inbound analysis failed for {}", msg.getClass().getSimpleName(), t);
        }
        if (!consume) ctx.fireChannelRead(msg);
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        try {
            session.onOutbound(msg);
            if (session.cfg.hideFromFmlHandshake) patchFmlHandshake(msg);
        } catch (Throwable t) {
            LeakScanMod.LOGGER.warn("outbound analysis failed", t);
        }
        super.write(ctx, msg, promise);
    }

    /**
     * The Forge handshake (login phase) sends the server the list of ALL client mods
     * (ModList.get().getMods(), verified against Forge 36.2.39 bytecode) — and the server writes
     * it into its logs. "Not being an FML mod" is impossible and there is no config switch, so on
     * the way out we replace the string "leakscan" with "optifine" — exactly the same length (8),
     * the string's VarInt length prefix doesn't change, the packet structure stays valid for any
     * payload format.
     */
    private static void patchFmlHandshake(Object msg) {
        String cn = Refl.classNameOf(msg);
        if (!cn.equals("CCustomPayloadLoginPacket")) return;
        try {
            Object ch = Refl.get(msg, net.minecraft.util.ResourceLocation.class);
            if (ch == null || !ch.toString().equalsIgnoreCase("fml:handshake")) return;
            io.netty.buffer.ByteBuf buf = Refl.get(msg, io.netty.buffer.ByteBuf.class);
            if (buf == null) return;
            int from = buf.readerIndex(), to = buf.writerIndex();
            byte[] repl = "optifine".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            byte[] find = "leakscan".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            for (int i = from; i + find.length <= to; i++) {
                boolean match = true;
                for (int k = 0; k < find.length; k++) {
                    if (buf.getByte(i + k) != find[k]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    for (int k = 0; k < repl.length; k++) buf.setByte(i + k, repl[k]);
                    i += repl.length - 1;
                }
            }
        } catch (Throwable t) {
            LeakScanMod.LOGGER.debug("fml handshake patch skipped", t);
        }
    }
}
