package dev.leakscan;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class ByteUtil {
    private ByteUtil() {}

    static Map<String, Object> kv(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(String.valueOf(kv[i]), kv[i + 1]);
        return m;
    }

    static <T> List<T> cap(List<T> l, int n) {
        return l.size() <= n ? l : l.subList(0, n);
    }

    /** VarInt-length-prefixed UTF-8 (the minecraft:brand format). */
    static String readVarString(byte[] b) {
        try {
            int pos = 0, len = 0, shift = 0, x;
            do {
                x = b[pos++];
                len |= (x & 0x7F) << shift;
                shift += 7;
            } while ((x & 0x80) != 0 && pos < 5);
            if (len >= 0 && pos + len <= b.length) return new String(b, pos, len, StandardCharsets.UTF_8);
        } catch (RuntimeException ignored) {
        }
        return runs(b, 200);
    }

    /**
     * Payload preview for the packet log: first tries an honest VarInt+UTF-8 parse (that is how
     * brand and many other string channels are built), but only if the result is non-empty and
     * doesn't look like garbage (no replacement characters) — otherwise (including when the first
     * byte of a binary channel accidentally parses as len=0, as with limboauth:mod) fall back to
     * runs(). Unlike readVarString(), an empty string (len=0) is not accepted — for a real binary
     * channel that is almost always a false positive, not an actually empty brand.
     */
    static String preview(byte[] b, int max) {
        String s = tryReadVarStringLoose(b);
        if (s != null && !s.isEmpty() && s.indexOf('\uFFFD') < 0) {
            return s.length() > max ? s.substring(0, max) : s;
        }
        return runs(b, max);
    }

    private static String tryReadVarStringLoose(byte[] b) {
        try {
            int pos = 0, len = 0, shift = 0, x;
            do {
                if (pos >= b.length || shift >= 35) return null;
                x = b[pos++];
                len |= (x & 0x7F) << shift;
                shift += 7;
            } while ((x & 0x80) != 0);
            if (len <= 0 || pos + len > b.length) return null;
            return new String(b, pos, len, StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Printable characters (UTF-8, including multibyte — Cyrillic, §-codes etc.), in runs of >=4
     * code points, from a binary payload. Previously only understood single-byte ASCII and broke
     * the string at every Cyrillic byte (e.g. "Your server (Purpur)" became " (Purpur)") — now it
     * decodes honestly. */
    static String runs(byte[] b, int max) {
        StringBuilder out = new StringBuilder();
        StringBuilder cur = new StringBuilder();
        int i = 0;
        while (i <= b.length) {
            int cp = -1, consumed = 1;
            if (i < b.length) {
                int c0 = b[i] & 0xFF;
                if (c0 < 0x80) {
                    cp = c0;
                } else if ((c0 & 0xE0) == 0xC0 && i + 1 < b.length && isCont(b[i + 1])) {
                    cp = ((c0 & 0x1F) << 6) | (b[i + 1] & 0x3F);
                    consumed = 2;
                } else if ((c0 & 0xF0) == 0xE0 && i + 2 < b.length && isCont(b[i + 1]) && isCont(b[i + 2])) {
                    cp = ((c0 & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F);
                    consumed = 3;
                } else if ((c0 & 0xF8) == 0xF0 && i + 3 < b.length && isCont(b[i + 1]) && isCont(b[i + 2]) && isCont(b[i + 3])) {
                    cp = ((c0 & 0x07) << 18) | ((b[i + 1] & 0x3F) << 12) | ((b[i + 2] & 0x3F) << 6) | (b[i + 3] & 0x3F);
                    consumed = 4;
                }
            }
            if (cp >= 0 && isPrintableCp(cp)) {
                cur.appendCodePoint(cp);
                i += consumed;
                continue;
            }
            if (cur.length() >= 4) {
                if (out.length() > 0) out.append(' ');
                out.append(cur);
            }
            cur.setLength(0);
            if (out.length() >= max) break;
            i++;
        }
        return out.length() > max ? out.substring(0, max) : out.toString();
    }

    private static boolean isCont(byte b) {
        return (b & 0xC0) == 0x80;
    }

    private static boolean isPrintableCp(int cp) {
        if (cp < 0x20 || cp == 0x7F) return false; // control characters, including NUL — break a run, not part of it
        int type = Character.getType(cp);
        return type != Character.CONTROL && type != Character.FORMAT && type != Character.SURROGATE
            && type != Character.PRIVATE_USE && type != Character.UNASSIGNED;
    }

    /** Strict: payload = one VarInt (length) + exactly that many UTF-8 bytes (plus a small tail of <=3 bytes).
     * null if that is not the case — unlike readVarString(), there is no fallback to runs() here, so
     * "the channel is just a string" can be reliably distinguished from "the channel is something else
     * that merely looks like one". */
    static String tryReadFullVarString(byte[] b) {
        try {
            int pos = 0, len = 0, shift = 0, x;
            do {
                if (pos >= b.length || shift >= 35) return null;
                x = b[pos++];
                len |= (x & 0x7F) << shift;
                shift += 7;
            } while ((x & 0x80) != 0);
            if (len < 0 || pos + len > b.length || b.length - (pos + len) > 3) return null;
            return new String(b, pos, len, StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            return null;
        }
    }

    static String hex(byte[] b, int max) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(b.length, max); i++) sb.append(String.format("%02x", b[i] & 0xFF));
        return sb.toString();
    }

    /**
     * A single-line safe version of an arbitrary string for reports/JSON: control characters
     * (including \n/\r/\t) collapse into spaces, backticks and vertical bars are replaced so
     * markdown markup and tables cannot be broken by anything a channel payload contains.
     */
    static String sanitizeInline(String s) {
        if (s == null || s.isEmpty()) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch < 0x20 || ch == 0x7F) sb.append(' ');
            else if (ch == '`') sb.append('\'');
            else if (ch == '|') sb.append('/');
            else sb.append(ch);
        }
        return sb.toString().trim();
    }
}
