package it.lpworks.jbmp.consumer.store;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import it.lpworks.jbmp.protocol.bgp.LargeCommunity;

/**
 * Helpers that render BGP attribute values into the textual / boxed forms the JDBC driver binds
 * for the {@code rib_state} upsert: {@code cidr}/{@code inet} address text, {@code timestamptz} as
 * an {@link OffsetDateTime}, and boxed arrays for {@code int4[]} / {@code text[]} columns. The
 * encodings match {@link RouteMonitorCopy} (and the reference relational model) so the historical
 * table and the current-state projection store identical values: extended communities as the hex
 * of their raw bytes, large communities as {@code global:local1:local2}.
 */
final class PgText {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private PgText() {
        throw new AssertionError("No instances");
    }

    /** {@code cidr} text {@code address/len}; the server canonicalises the address. */
    static String cidr(byte[] prefix, int len, boolean ipv4) {
        if (prefix == null || prefix.length == 0) {
            return (ipv4 ? "0.0.0.0/" : "::/") + len;
        }
        return ip(prefix, ipv4 ? 4 : 16) + "/" + len;
    }

    /** {@code inet} host-address text, or {@code null} when absent. */
    static String inet(byte[] addr) {
        if (addr == null || addr.length == 0) {
            return null;
        }
        return ip(addr, addr.length == 16 ? 16 : 4);
    }

    /** {@code timestamptz} value from nanoseconds since the Unix epoch. */
    static OffsetDateTime ts(long nanos) {
        Instant instant = Instant.ofEpochSecond(Math.floorDiv(nanos, 1_000_000_000L),
                Math.floorMod(nanos, 1_000_000_000L));
        return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    /** Boxes an AS array as signed 32-bit ints ({@code int4}), matching the reference encoding. */
    static Integer[] asnArray(long[] asns) {
        if (asns == null || asns.length == 0) {
            return null;
        }
        Integer[] out = new Integer[asns.length];
        for (int i = 0; i < asns.length; i++) {
            out[i] = (int) asns[i];
        }
        return out;
    }

    /** Boxes an {@code int[]} (community values) as {@code int4} elements. */
    static Integer[] intArray(int[] values) {
        if (values == null || values.length == 0) {
            return null;
        }
        Integer[] out = new Integer[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = values[i];
        }
        return out;
    }

    /** Large communities as {@code global:local1:local2} text-array elements. */
    static String[] largeCommunities(List<LargeCommunity> lcs) {
        if (lcs == null || lcs.isEmpty()) {
            return null;
        }
        return lcs.stream()
                .map(lc -> lc.globalAdministrator() + ":" + lc.localData1() + ":" + lc.localData2())
                .toArray(String[]::new);
    }

    /** Extended communities as the lower-case hex of their raw bytes. */
    static String[] extCommunities(List<byte[]> ecs) {
        if (ecs == null || ecs.isEmpty()) {
            return null;
        }
        return ecs.stream().map(PgText::hex).toArray(String[]::new);
    }

    /** A {@code text[]} from a string list, or {@code null} when empty. */
    static String[] strings(List<String> items) {
        if (items == null || items.isEmpty()) {
            return null;
        }
        return items.toArray(String[]::new);
    }

    private static String ip(byte[] addr, int width) {
        byte[] full = addr.length == width ? addr : new byte[width];
        if (full != addr) {
            System.arraycopy(addr, 0, full, 0, Math.min(addr.length, width));
        }
        try {
            return InetAddress.getByAddress(full).getHostAddress();
        } catch (UnknownHostException e) {
            return hex(addr);
        }
    }

    private static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }
}
