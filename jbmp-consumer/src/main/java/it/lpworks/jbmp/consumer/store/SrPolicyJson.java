package it.lpworks.jbmp.consumer.store;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Builds the structured-JSON representation of a BGP Segment Routing Policy (SR Policy)
 * NLRI from the raw NLRI bytes, for storage alongside the other per-route attributes.
 *
 * <p>SR Policy is carried in BGP with SAFI 73 as defined by
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-idr-segment-routing-te-policy/">
 * draft-ietf-idr-segment-routing-te-policy</a>. The NLRI value, as it appears inside an
 * MP_REACH_NLRI / MP_UNREACH_NLRI attribute (RFC 4760), is a sequence of records, each
 * preceded by a one-octet <em>NLRI length expressed in bits</em>. Each record body is:
 *
 * <pre>
 *   +------------------+
 *   | Distinguisher (4)|   uint32, big-endian
 *   +------------------+
 *   | Policy Color  (4)|   uint32, big-endian
 *   +------------------+
 *   | Endpoint (4|16)  |   IPv4 (4 octets) or IPv6 (16 octets)
 *   +------------------+
 * </pre>
 *
 * <p>The endpoint length (and therefore the value of {@code endpoint_afi}) is governed by
 * the AFI of the enclosing MP attribute, <strong>not</strong> by anything inside the NLRI
 * bytes themselves. The single-argument {@link #toJson(byte[])} therefore assumes an IPv4
 * endpoint (AFI 1); callers that know the family carry an IPv6 endpoint should use
 * {@link #toJson(byte[], int)} so the 16-octet endpoint is decoded correctly.
 *
 * <h2>Output shape</h2>
 * <p>The result is a JSON array (one object per policy record) whose objects always carry
 * these four fields, in this order:
 * <ul>
 *   <li>{@code distinguisher} — the policy distinguisher (unsigned 32-bit integer);</li>
 *   <li>{@code color} — the policy colour (unsigned 32-bit integer);</li>
 *   <li>{@code endpoint} — the endpoint address as a string;</li>
 *   <li>{@code endpoint_afi} — the AFI used to interpret the endpoint (1 = IPv4, 2 = IPv6).</li>
 * </ul>
 *
 * <h2>Zero data loss</h2>
 * <p>This decoder never throws and never silently discards bytes. If a record's bit-length
 * prefix over-runs the buffer, or a record body is too short to hold a distinguisher, a
 * colour and an endpoint, the undecodable remainder is emitted as a single trailing object
 * carrying a {@code "raw"} field with the hex of the leftover bytes (and a {@code "len"}
 * field with their count) so nothing is dropped. If the whole input cannot be framed with
 * bit-length prefixes, the bytes are reinterpreted as a sequence of fixed-size records with
 * no length prefix (some senders omit it); should that also yield nothing, the entire input
 * is preserved as one {@code "raw"} object.
 *
 * <p>The JSON is assembled by hand (no external JSON library) to match the manual encoding
 * used elsewhere in this package. The class is stateless and thread-safe.
 */
public final class SrPolicyJson {

    /** AFI: IPv4 (4-octet endpoint). */
    private static final int AFI_IPV4 = 1;

    /** AFI: IPv6 (16-octet endpoint). */
    private static final int AFI_IPV6 = 2;

    /** Distinguisher (4) + Color (4) fixed prefix of every record body. */
    private static final int FIXED_PREFIX = 8;

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private SrPolicyJson() {
        throw new AssertionError("No instances");
    }

    /**
     * Decodes SR Policy NLRI bytes into the structured-JSON representation, assuming an
     * IPv4 (4-octet) endpoint.
     *
     * @param raw the raw SR Policy NLRI bytes (the bit-length-prefixed records as carried
     *            in an MP_REACH_NLRI / MP_UNREACH_NLRI attribute); may be {@code null}
     * @return the JSON array string, or {@code null} when {@code raw} is {@code null} or empty
     */
    public static String toJson(byte[] raw) {
        return toJson(raw, AFI_IPV4);
    }

    /**
     * Decodes SR Policy NLRI bytes into the structured-JSON representation for the given AFI.
     *
     * <p>The endpoint is read as 16 octets when {@code afi} is 2 (IPv6) and as 4 octets
     * otherwise. The {@code afi} value is echoed verbatim into each object's
     * {@code endpoint_afi} field.
     *
     * @param raw the raw SR Policy NLRI bytes; may be {@code null}
     * @param afi the Address Family Identifier of the enclosing MP attribute (1 = IPv4,
     *            2 = IPv6)
     * @return the JSON array string, or {@code null} when {@code raw} is {@code null} or empty
     */
    public static String toJson(byte[] raw, int afi) {
        if (raw == null || raw.length == 0) {
            return null;
        }
        int endpointLen = (afi == AFI_IPV6) ? 16 : 4;

        StringBuilder out = new StringBuilder(64);
        out.append('[');
        boolean any = decodeBitLength(raw, afi, endpointLen, out);
        if (!any) {
            // No bit-length-framed record decoded: retry without the length prefix.
            out.setLength(1); // keep the leading '['
            any = decodeFixed(raw, afi, endpointLen, out);
        }
        if (!any) {
            // Nothing could be framed at all: preserve the whole input verbatim.
            out.setLength(1);
            appendRawObject(out, raw, 0, raw.length, false);
        }
        out.append(']');
        return out.toString();
    }

    /**
     * Decodes the bit-length-prefixed framing. Returns {@code true} if at least one byte was
     * consumed as a record (or captured as a raw remainder), {@code false} if no prefix could
     * be read at all.
     */
    private static boolean decodeBitLength(byte[] raw, int afi, int endpointLen,
            StringBuilder out) {
        int recordLen = FIXED_PREFIX + endpointLen;
        int offset = 0;
        boolean any = false;
        while (offset < raw.length) {
            int bitLen = raw[offset] & 0xFF;
            int byteLen = (bitLen + 7) / 8;
            int bodyStart = offset + 1;
            if (byteLen == 0 || bodyStart + byteLen > raw.length) {
                // Prefix over-runs the buffer (or is degenerate): preserve the remainder.
                appendRawObject(out, raw, offset, raw.length - offset, any);
                return true;
            }
            if (byteLen < recordLen) {
                // Body too short for distinguisher + color + endpoint: preserve it raw and
                // advance so well-formed records that follow are still decoded.
                appendRawObject(out, raw, bodyStart, byteLen, any);
                any = true;
                offset = bodyStart + byteLen;
                continue;
            }
            appendPolicyObject(out, raw, bodyStart, endpointLen, afi, any);
            any = true;
            offset = bodyStart + byteLen;
        }
        return any;
    }

    /**
     * Decodes fixed-size records with no bit-length prefix. Returns {@code true} if at least
     * one record (or a raw remainder) was emitted.
     */
    private static boolean decodeFixed(byte[] raw, int afi, int endpointLen, StringBuilder out) {
        int recordLen = FIXED_PREFIX + endpointLen;
        int offset = 0;
        boolean any = false;
        while (offset + recordLen <= raw.length) {
            appendPolicyObject(out, raw, offset, endpointLen, afi, any);
            any = true;
            offset += recordLen;
        }
        if (any && offset < raw.length) {
            // Trailing bytes that do not form a full record: keep them verbatim.
            appendRawObject(out, raw, offset, raw.length - offset, true);
        }
        return any;
    }

    /**
     * Appends one {@code {distinguisher,color,endpoint,endpoint_afi}} object. The endpoint
     * begins at {@code bodyStart + 8}; if it cannot be rendered as an address its hex is used.
     */
    private static void appendPolicyObject(StringBuilder out, byte[] raw, int bodyStart,
            int endpointLen, int afi, boolean comma) {
        if (comma) {
            out.append(',');
        }
        long distinguisher = readUint32(raw, bodyStart);
        long color = readUint32(raw, bodyStart + 4);
        int epStart = bodyStart + FIXED_PREFIX;
        String endpoint = formatAddress(raw, epStart, endpointLen);

        out.append("{\"distinguisher\":").append(distinguisher)
                .append(",\"color\":").append(color)
                .append(",\"endpoint\":\"").append(escape(endpoint)).append('"')
                .append(",\"endpoint_afi\":").append(afi)
                .append('}');
    }

    /** Appends a {@code {"raw":"<hex>","len":N}} object preserving undecodable bytes. */
    private static void appendRawObject(StringBuilder out, byte[] raw, int start, int len,
            boolean comma) {
        if (comma) {
            out.append(',');
        }
        out.append("{\"raw\":\"").append(hex(raw, start, len))
                .append("\",\"len\":").append(len).append('}');
    }

    /**
     * Renders {@code len} octets at {@code start} as an IP address string, falling back to a
     * bare hex string when the slice is not a valid 4- or 16-octet address.
     */
    private static String formatAddress(byte[] raw, int start, int len) {
        byte[] addr = new byte[len];
        System.arraycopy(raw, start, addr, 0, len);
        try {
            InetAddress ip = (len == 4)
                    ? Inet4Address.getByAddress(addr)
                    : InetAddress.getByAddress(addr);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            // Not a legal address length: keep the bytes as hex so nothing is lost.
            return hex(addr, 0, len);
        }
    }

    private static long readUint32(byte[] b, int off) {
        return ((long) (b[off] & 0xFF) << 24)
                | ((long) (b[off + 1] & 0xFF) << 16)
                | ((long) (b[off + 2] & 0xFF) << 8)
                | (b[off + 3] & 0xFF);
    }

    private static String hex(byte[] bytes, int start, int len) {
        char[] out = new char[len * 2];
        for (int i = 0; i < len; i++) {
            int v = bytes[start + i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /** Minimal RFC 8259 string escaping for the values this class can emit. */
    private static String escape(String s) {
        StringBuilder b = null;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            String rep = switch (c) {
                case '"' -> "\\\"";
                case '\\' -> "\\\\";
                case '\n' -> "\\n";
                case '\r' -> "\\r";
                case '\t' -> "\\t";
                case '\b' -> "\\b";
                case '\f' -> "\\f";
                default -> (c < 0x20) ? String.format("\\u%04x", (int) c) : null;
            };
            if (rep == null) {
                if (b != null) {
                    b.append(c);
                }
            } else {
                if (b == null) {
                    b = new StringBuilder(s.length() + 8).append(s, 0, i);
                }
                b.append(rep);
            }
        }
        return (b == null) ? s : b.toString();
    }
}
