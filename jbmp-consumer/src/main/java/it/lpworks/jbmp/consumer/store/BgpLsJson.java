package it.lpworks.jbmp.consumer.store;

import java.nio.charset.StandardCharsets;

/**
 * Decoder that turns the raw value of a BGP Link-State (BGP-LS) path attribute into a
 * structured JSON string for storage alongside the route.
 *
 * <p>The BGP-LS path attribute (RFC 7752 §3.3, attribute type code 29) carries a sequence of
 * Link-State TLVs. Each TLV is framed as a 2-octet Type, a 2-octet Length and a Length-octet
 * Value:
 *
 * <pre>{@code
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              Type             |             Length            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  //                            Value (variable)                //
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * }</pre>
 *
 * <p>The bytes handed to {@link #toJson(byte[])} are exactly the attribute <em>value</em> (the
 * TLV sequence), so parsing begins at offset {@code 0}. The TLV type codes decoded here are the
 * Node / Link / Prefix descriptors of RFC 7752 §3.2 and the link/node attribute TLVs of
 * RFC 7752 §3.3 (some originally defined for IS-IS/OSPF traffic-engineering in RFC 5305 /
 * RFC 3630 and carried into BGP-LS). TLV types whose semantics are not specially decoded keep
 * their value as the lower-case hexadecimal of the raw value octets, so no information is ever
 * dropped.
 *
 * <h2>Emitted JSON shape</h2>
 * <pre>{@code
 *   {"tlvs":[{"type":N,"type_str":"...","length":N,"value":<value>}, ...],"raw_len":N}
 * }</pre>
 *
 * <p>The {@code value} is rendered to match the structured representation this collector stores:
 * unsigned 32-bit quantities as JSON numbers, IPv4/IPv6 addresses as their textual form, a MAC /
 * IS-IS system identifier as colon- or dot-grouped hexadecimal, bandwidths (IEEE&nbsp;754
 * single-precision, RFC 3630) as their integral byte/second value rendered as a string, and the
 * Link Local/Remote Identifier (RFC 5307) as a {@code {"local":N,"remote":N}} object. IP address
 * text is produced with the same compression rules as the reference representation (dotted-quad
 * for IPv4, RFC 5952 zero-compression for IPv6) so the two systems agree byte for byte.
 *
 * <h2>Robustness</h2>
 * <p>The decoder never throws and never loses data. A TLV whose declared length runs past the
 * end of the buffer terminates the scan (mirroring the reference parser). A known TLV whose value
 * is shorter than its fixed layout falls back to the raw hexadecimal of its octets rather than
 * guessing. All emitted strings are JSON-escaped.
 *
 * <p>The class is stateless and thread-safe.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7752">RFC 7752 — North-Bound Distribution of
 *      Link-State and TE Information Using BGP</a>
 */
public final class BgpLsJson {

    // Node Descriptor TLVs (RFC 7752 §3.2.1.4).
    private static final int TLV_AUTONOMOUS_SYSTEM = 512;
    private static final int TLV_BGP_LS_IDENTIFIER = 513;
    private static final int TLV_OSPF_AREA_ID = 514;
    private static final int TLV_IGP_ROUTER_ID = 515;

    // Link Descriptor TLVs (RFC 7752 §3.2.2 / RFC 5307).
    private static final int TLV_LINK_LOCAL_REMOTE_ID = 258;
    private static final int TLV_LOCAL_INTERFACE_IP = 259;
    private static final int TLV_REMOTE_INTERFACE_IP = 260;

    // Prefix Descriptor TLVs (RFC 7752 §3.2.3).
    private static final int TLV_OSPF_ROUTE_TYPE = 264;
    private static final int TLV_IP_REACHABILITY_INFO = 265;

    // Node Attribute TLVs (RFC 7752 §3.3.1).
    private static final int TLV_NODE_NAME = 1026;
    private static final int TLV_ISIS_AREA_ID = 1027;
    private static final int TLV_IGP_ROUTER_ID_ATTR = 1028;

    // Link Attribute TLVs (RFC 7752 §3.3.2 / RFC 5305 / RFC 3630).
    private static final int TLV_ADMIN_GROUP = 1088;
    private static final int TLV_MAX_LINK_BW = 1089;
    private static final int TLV_MAX_RESERVABLE_BW = 1090;
    private static final int TLV_UNRESERVED_BW = 1091;
    private static final int TLV_TE_DEFAULT_METRIC = 1092;
    private static final int TLV_IGP_METRIC = 1095;

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private BgpLsJson() {
        throw new AssertionError("No instances");
    }

    /**
     * Decodes the raw value of a BGP-LS path attribute (the TLV sequence, RFC 7752 §3.3) into a
     * structured JSON string.
     *
     * @param raw the attribute value octets (the TLV sequence), parsed from offset {@code 0}
     * @return the JSON document {@code {"tlvs":[...],"raw_len":N}}, or {@code null} when
     *         {@code raw} is {@code null} or empty
     */
    public static String toJson(byte[] raw) {
        if (raw == null || raw.length == 0) {
            return null;
        }

        StringBuilder tlvs = new StringBuilder();
        int count = 0;
        int offset = 0;
        // Each TLV needs at least the 4-octet Type/Length header.
        while (offset + 4 <= raw.length) {
            int type = u16(raw, offset);
            int len = u16(raw, offset + 2);
            offset += 4;
            // A length that overruns the buffer terminates the scan; the already-parsed TLVs and
            // the original raw_len are still emitted so nothing seen so far is lost.
            if (offset + len > raw.length) {
                break;
            }
            if (count > 0) {
                tlvs.append(',');
            }
            tlvs.append("{\"type\":").append(type)
                .append(",\"type_str\":\"").append(typeString(type)).append('"')
                .append(",\"length\":").append(len)
                .append(",\"value\":");
            appendValue(tlvs, type, raw, offset, len);
            tlvs.append('}');
            offset += len;
            count++;
        }

        StringBuilder out = new StringBuilder(tlvs.length() + 32);
        // The reference emits a JSON null for the array when no TLVs were parsed.
        out.append("{\"tlvs\":");
        if (count == 0) {
            out.append("null");
        } else {
            out.append('[').append(tlvs).append(']');
        }
        out.append(",\"raw_len\":").append(raw.length).append('}');
        return out.toString();
    }

    /**
     * Appends the JSON {@code value} for a single TLV. Known types are rendered structurally;
     * everything else (and any known type that is too short to parse) falls back to the lower-case
     * hexadecimal of the value octets, preserving the data.
     */
    private static void appendValue(StringBuilder b, int type, byte[] data, int off, int len) {
        switch (type) {
            case TLV_AUTONOMOUS_SYSTEM, TLV_BGP_LS_IDENTIFIER, TLV_ADMIN_GROUP,
                 TLV_TE_DEFAULT_METRIC -> {
                if (len >= 4) {
                    b.append(u32(data, off));
                    return;
                }
            }
            case TLV_OSPF_AREA_ID -> {
                if (len >= 4) {
                    appendQuoted(b, ipString(data, off, 4));
                    return;
                }
            }
            case TLV_IGP_ROUTER_ID, TLV_IGP_ROUTER_ID_ATTR -> {
                // 4 octets (OSPF router-id as IPv4), 6/7/8 octets (IS-IS system-id, optionally
                // with a pseudonode octet), otherwise raw hex.
                switch (len) {
                    case 4 -> {
                        appendQuoted(b, ipString(data, off, 4));
                        return;
                    }
                    case 6 -> {
                        appendQuoted(b, dottedHex(data, off, new int[] {2, 2, 2}));
                        return;
                    }
                    case 7 -> {
                        appendQuoted(b, dottedHex(data, off, new int[] {2, 2, 2, 1}));
                        return;
                    }
                    case 8 -> {
                        appendQuoted(b, dottedHex(data, off, new int[] {2, 2, 2, 2}));
                        return;
                    }
                    default -> { /* fall through to raw hex */ }
                }
            }
            case TLV_LINK_LOCAL_REMOTE_ID -> {
                if (len >= 8) {
                    b.append("{\"local\":").append(u32(data, off))
                     .append(",\"remote\":").append(u32(data, off + 4)).append('}');
                    return;
                }
            }
            case TLV_LOCAL_INTERFACE_IP, TLV_REMOTE_INTERFACE_IP -> {
                if (len == 4 || len == 16) {
                    appendQuoted(b, ipString(data, off, len));
                    return;
                }
            }
            case TLV_OSPF_ROUTE_TYPE -> {
                if (len >= 1) {
                    b.append(data[off] & 0xFF);
                    return;
                }
            }
            case TLV_IP_REACHABILITY_INFO -> {
                if (len >= 1) {
                    int prefixLen = data[off] & 0xFF;
                    int numBytes = (prefixLen + 7) / 8;
                    if (1 + numBytes <= len) {
                        // The reference builds a full 16-octet address and stringifies it, so an
                        // IPv4 prefix is rendered with IPv6 compression rules unless it is a
                        // v4-mapped address; replicate that exactly.
                        byte[] ip = new byte[16];
                        System.arraycopy(data, off + 1, ip, 0, numBytes);
                        appendQuoted(b, ipString(ip, 0, 16) + "/" + prefixLen);
                        return;
                    }
                }
            }
            case TLV_NODE_NAME -> {
                appendQuoted(b, new String(data, off, len, StandardCharsets.UTF_8));
                return;
            }
            case TLV_ISIS_AREA_ID -> {
                appendQuoted(b, hex(data, off, len));
                return;
            }
            case TLV_MAX_LINK_BW, TLV_MAX_RESERVABLE_BW -> {
                if (len >= 4) {
                    appendQuoted(b, bandwidth(u32(data, off)));
                    return;
                }
            }
            case TLV_UNRESERVED_BW -> {
                if (len >= 32) {
                    b.append('[');
                    for (int i = 0; i < 8; i++) {
                        if (i > 0) {
                            b.append(',');
                        }
                        appendQuoted(b, bandwidth(u32(data, off + i * 4)));
                    }
                    b.append(']');
                    return;
                }
            }
            case TLV_IGP_METRIC -> {
                switch (len) {
                    case 1 -> {
                        b.append(data[off] & 0xFF);
                        return;
                    }
                    case 2 -> {
                        b.append(u16(data, off));
                        return;
                    }
                    case 3 -> {
                        b.append(((long) (data[off] & 0xFF) << 16)
                                | ((data[off + 1] & 0xFF) << 8)
                                | (data[off + 2] & 0xFF));
                        return;
                    }
                    case 4 -> {
                        b.append(u32(data, off));
                        return;
                    }
                    default -> { /* fall through to raw hex */ }
                }
            }
            default -> { /* fall through to raw hex */ }
        }
        // Unknown type, or a known type whose value was too short / an unexpected length.
        appendQuoted(b, hex(data, off, len));
    }

    /** Maps a TLV type code to the reference's {@code type_str} label. */
    private static String typeString(int type) {
        return switch (type) {
            case TLV_AUTONOMOUS_SYSTEM -> "autonomous_system";
            case TLV_BGP_LS_IDENTIFIER -> "bgp_ls_identifier";
            case TLV_OSPF_AREA_ID -> "ospf_area_id";
            case TLV_IGP_ROUTER_ID -> "igp_router_id";
            case TLV_LINK_LOCAL_REMOTE_ID -> "link_local_remote_id";
            case TLV_LOCAL_INTERFACE_IP -> "local_interface_ip";
            case TLV_REMOTE_INTERFACE_IP -> "remote_interface_ip";
            case TLV_OSPF_ROUTE_TYPE -> "ospf_route_type";
            case TLV_IP_REACHABILITY_INFO -> "ip_reachability_info";
            case TLV_NODE_NAME -> "node_name";
            case TLV_ISIS_AREA_ID -> "isis_area_id";
            case TLV_IGP_ROUTER_ID_ATTR -> "igp_router_id_attr";
            case TLV_ADMIN_GROUP -> "admin_group";
            case TLV_MAX_LINK_BW -> "max_link_bandwidth";
            case TLV_MAX_RESERVABLE_BW -> "max_reservable_bandwidth";
            case TLV_UNRESERVED_BW -> "unreserved_bandwidth";
            case TLV_TE_DEFAULT_METRIC -> "te_default_metric";
            case TLV_IGP_METRIC -> "igp_metric";
            default -> "unknown_" + type;
        };
    }

    // ------------------------------------------------------------------
    // Value formatting helpers.
    // ------------------------------------------------------------------

    /**
     * Formats an IEEE 754 single-precision bandwidth (RFC 3630, bytes/second) as its integral
     * value with no fractional part, matching {@code fmt.Sprintf("%.0f", ...)}.
     */
    private static String bandwidth(long bits) {
        float f = Float.intBitsToFloat((int) bits);
        // Render with no decimals; Java's Math.round half-up matches Go's %.0f rounding.
        return Long.toString(Math.round((double) f));
    }

    /**
     * Renders {@code count} octets at {@code off} as a textual IP address using the same rules as
     * the reference (Go {@code net.IP.String()}): a 4-octet address as dotted-quad, a 16-octet
     * address as an IPv4-mapped dotted-quad when applicable, otherwise RFC 5952 compressed IPv6.
     */
    private static String ipString(byte[] data, int off, int count) {
        byte[] addr = new byte[count];
        System.arraycopy(data, off, addr, 0, count);
        if (count == 4) {
            return dotted(addr, 0);
        }
        if (count == 16) {
            // v4-mapped: ::ffff:a.b.c.d  (first 10 octets zero, octets 10-11 == 0xff).
            boolean mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    mapped = false;
                    break;
                }
            }
            if (mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                return dotted(addr, 12);
            }
            return ipv6(addr);
        }
        // Unexpected length: fall back to plain hex so nothing is lost.
        return hex(addr, 0, count);
    }

    /** Formats four octets at {@code off} as a dotted-quad IPv4 string. */
    private static String dotted(byte[] addr, int off) {
        return (addr[off] & 0xFF) + "." + (addr[off + 1] & 0xFF) + "."
                + (addr[off + 2] & 0xFF) + "." + (addr[off + 3] & 0xFF);
    }

    /**
     * Formats a 16-octet IPv6 address with RFC 5952 zero compression, matching Go's
     * {@code net.IP.String()}: the longest run of two or more zero 16-bit groups is replaced by
     * {@code ::} (the first such run on a tie), groups are lower-case hexadecimal with no leading
     * zeros.
     */
    private static String ipv6(byte[] addr) {
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((addr[i * 2] & 0xFF) << 8) | (addr[i * 2 + 1] & 0xFF);
        }
        // Find the longest run of zero groups (length >= 2) to compress.
        int bestStart = -1;
        int bestLen = 0;
        int curStart = -1;
        int curLen = 0;
        for (int i = 0; i < 8; i++) {
            if (groups[i] == 0) {
                if (curStart < 0) {
                    curStart = i;
                    curLen = 1;
                } else {
                    curLen++;
                }
                if (curLen > bestLen) {
                    bestLen = curLen;
                    bestStart = curStart;
                }
            } else {
                curStart = -1;
                curLen = 0;
            }
        }
        if (bestLen < 2) {
            bestStart = -1;
            bestLen = 0;
        }

        StringBuilder b = new StringBuilder(39);
        int i = 0;
        while (i < 8) {
            if (i == bestStart) {
                // Emit the compressed run as "::" (covers a leading or trailing run too).
                b.append("::");
                i += bestLen;
                continue;
            }
            if (i > 0 && i != bestStart) {
                // Separator between groups, unless the previous token already ended in ':'.
                if (b.length() == 0 || b.charAt(b.length() - 1) != ':') {
                    b.append(':');
                }
            }
            b.append(Integer.toHexString(groups[i]));
            i++;
        }
        return b.toString();
    }

    /**
     * Renders a group-dotted lower-case hexadecimal identifier (e.g. an IS-IS system-id as
     * {@code aaaa.bbbb.cccc}). Each entry in {@code groupSizes} is the number of octets in that
     * group, the groups joined by {@code '.'}.
     */
    private static String dottedHex(byte[] data, int off, int[] groupSizes) {
        StringBuilder b = new StringBuilder();
        int p = off;
        for (int g = 0; g < groupSizes.length; g++) {
            if (g > 0) {
                b.append('.');
            }
            for (int i = 0; i < groupSizes[g]; i++) {
                int v = data[p++] & 0xFF;
                b.append(HEX[v >>> 4]).append(HEX[v & 0x0F]);
            }
        }
        return b.toString();
    }

    // ------------------------------------------------------------------
    // Primitive readers and JSON utilities.
    // ------------------------------------------------------------------

    private static int u16(byte[] data, int off) {
        return ((data[off] & 0xFF) << 8) | (data[off + 1] & 0xFF);
    }

    private static long u32(byte[] data, int off) {
        return ((long) (data[off] & 0xFF) << 24)
                | ((data[off + 1] & 0xFF) << 16)
                | ((data[off + 2] & 0xFF) << 8)
                | (data[off + 3] & 0xFF);
    }

    private static String hex(byte[] data, int off, int len) {
        char[] out = new char[len * 2];
        for (int i = 0; i < len; i++) {
            int v = data[off + i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /** Appends a JSON-escaped, double-quoted string. */
    private static void appendQuoted(StringBuilder b, String s) {
        b.append('"');
        escape(b, s);
        b.append('"');
    }

    /** Appends {@code s} with JSON string escaping (RFC 8259 §7). */
    private static void escape(StringBuilder b, String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                default -> {
                    if (c < 0x20) {
                        b.append("\\u").append(HEX[(c >> 12) & 0xF]).append(HEX[(c >> 8) & 0xF])
                         .append(HEX[(c >> 4) & 0xF]).append(HEX[c & 0xF]);
                    } else {
                        b.append(c);
                    }
                }
            }
        }
    }
}
