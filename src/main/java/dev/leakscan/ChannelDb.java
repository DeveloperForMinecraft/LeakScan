package dev.leakscan;

import java.util.LinkedHashMap;

/**
 * One DB per SERVER (not per session): <gameDir>/leakscan/channel-db/<host>.json.
 * Accumulates across visits so channel patterns are visible even if the server only sent
 * 1-2 packets in it during a single session.
 */
final class ChannelDb {
    LinkedHashMap<String, Entry> channels = new LinkedHashMap<>();

    static final class Entry {
        long totalPackets;
        long firstSeenMs;
        long lastSeenMs;
        /** hex sample (first N bytes of the payload) -> how many times it occurred. LinkedHashMap = appearance order. */
        LinkedHashMap<String, Integer> samples = new LinkedHashMap<>();
    }
}
