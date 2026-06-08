package it.lpworks.jbmp.consumer.store;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Renders an Ethernet VPN (EVPN) NLRI route into a compact, structured JSON object
 * string, matching the field names and omit-empty semantics of the structured
 * representation used for long-term storage.
 *
 * <p>EVPN routes are defined by RFC 7432 §7 (with the Route Type 5 IP Prefix route
 * defined by RFC 9136). On the wire an EVPN NLRI is a 1-octet Route Type, a 1-octet
 * Length and a type-specific <em>Route Type Specific</em> field. This decoder receives
 * the Route Type as a separate argument and the Route Type Specific field as the
 * {@code raw} byte array; the leading 1-octet Route Type and 1-octet Length are
 * <strong>not</strong> part of {@code raw}.
 *
 * <h2>Produced fields</h2>
 * <p>The JSON object always carries {@code route_type} (integer), {@code route_type_str}
 * (a stable mnemonic) and {@code rd} (the Route Distinguisher, RFC 4364 §4.2). The
 * remaining fields are emitted only when present and non-zero, mirroring the storage
 * schema's omit-empty behaviour:
 * <ul>
 *   <li>{@code esi} — the 10-octet Ethernet Segment Identifier, colon-hex;</li>
 *   <li>{@code ethernet_tag} — the 4-octet Ethernet Tag ID;</li>
 *   <li>{@code mac} / {@code mac_len} — the MAC address (colon-hex) and its bit length;</li>
 *   <li>{@code ip} / {@code ip_len} — the IP address and its bit length;</li>
 *   <li>{@code mpls_label1} / {@code mpls_label2} — the 20-bit MPLS labels;</li>
 *   <li>{@code gateway_ip} — the Type 5 gateway IP address;</li>
 *   <li>{@code prefix_len} — the Type 5 IP prefix length.</li>
 * </ul>
 *
 * <h2>Per-route-type layout (Route Type Specific field, RFC 7432 §7.1–§7.5, RFC 9136)</h2>
 * <ul>
 *   <li>Type 1 (Ethernet Auto-Discovery): RD(8) ESI(10) EthernetTag(4) [MPLS(3)].</li>
 *   <li>Type 2 (MAC/IP Advertisement): RD(8) ESI(10) EthernetTag(4) MACLen(1) MAC(6)
 *       IPLen(1) IP(0/4/16) [MPLS1(3)] [MPLS2(3)].</li>
 *   <li>Type 3 (Inclusive Multicast Ethernet Tag): RD(8) EthernetTag(4) IPLen(1)
 *       OriginatingRouterIP(4/16).</li>
 *   <li>Type 4 (Ethernet Segment): RD(8) ESI(10) IPLen(1) OriginatingRouterIP(4/16).</li>
 *   <li>Type 5 (IP Prefix, RFC 9136): RD(8) ESI(10) EthernetTag(4) IPPrefixLen(1)
 *       IPPrefix(4/16) GatewayIP(4/16) [MPLS(3)].</li>
 * </ul>
 *
 * <h2>Robustness</h2>
 * <p>This decoder never throws and never silently drops bytes. Lengths and IP-field
 * widths are derived exactly as the storage schema does; if the supplied bytes are
 * shorter than a field requires, that field is simply omitted. As a last-resort safety
 * net, any failure to interpret the bytes results in an additional {@code raw} field
 * carrying the full input as lowercase hex, so no information is lost.
 *
 * <p>This class is stateless and thread-safe.
 */
public final class EvpnJson {

    /** EVPN Route Type 1 — Ethernet Auto-Discovery route (RFC 7432 §7.1). */
    private static final int TYPE_ETHERNET_AUTO_DISCOVERY = 1;

    /** EVPN Route Type 2 — MAC/IP Advertisement route (RFC 7432 §7.2). */
    private static final int TYPE_MAC_IP = 2;

    /** EVPN Route Type 3 — Inclusive Multicast Ethernet Tag route (RFC 7432 §7.3). */
    private static final int TYPE_INCLUSIVE_MULTICAST = 3;

    /** EVPN Route Type 4 — Ethernet Segment route (RFC 7432 §7.4). */
    private static final int TYPE_ETHERNET_SEGMENT = 4;

    /** EVPN Route Type 5 — IP Prefix route (RFC 9136). */
    private static final int TYPE_IP_PREFIX = 5;

    /** Route Distinguisher width in octets (RFC 4364 §4.2). */
    private static final int RD_LEN = 8;

    /** Ethernet Segment Identifier width in octets (RFC 7432 §5). */
    private static final int ESI_LEN = 10;

    /** Ethernet Tag ID width in octets (RFC 7432 §7). */
    private static final int ETAG_LEN = 4;

    /** MPLS label entry width in octets (RFC 3032). */
    private static final int LABEL_LEN = 3;

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private EvpnJson() {
        throw new AssertionError("No instances");
    }

    /**
     * Renders one EVPN route to a structured JSON object string.
     *
     * @param routeType the EVPN Route Type (RFC 7432 §7); supplied separately because it
     *                  is not part of {@code raw}
     * @param raw       the Route Type Specific field exactly as stored (the 1-octet Route
     *                  Type and 1-octet Length having already been stripped); may be
     *                  {@code null} or empty
     * @return the JSON object string, or {@code null} when {@code raw} is {@code null} or
     *         empty
     */
    public static String toJson(int routeType, byte[] raw) {
        if (raw == null || raw.length == 0) {
            return null;
        }

        StringBuilder b = new StringBuilder(128);
        b.append('{');
        appendNumber(b, "route_type", routeType & 0xFF);
        b.append(',');
        appendString(b, "route_type_str", routeTypeString(routeType));

        try {
            switch (routeType) {
                case TYPE_ETHERNET_AUTO_DISCOVERY -> type1(b, raw);
                case TYPE_MAC_IP -> type2(b, raw);
                case TYPE_INCLUSIVE_MULTICAST -> type3(b, raw);
                case TYPE_ETHERNET_SEGMENT -> type4(b, raw);
                case TYPE_IP_PREFIX -> type5(b, raw);
                default -> appendRd(b, raw);
            }
        } catch (RuntimeException e) {
            // Last-resort safety net: never throw, never drop data. Whatever could not be
            // interpreted is preserved as the full input rendered to hex.
            b.append(',');
            appendString(b, "raw", hex(raw));
        }

        return b.append('}').toString();
    }

    // ------------------------------------------------------------------
    // Per-route-type field extraction (offsets match the stored layout).
    // ------------------------------------------------------------------

    /** Type 1 — RD(8) ESI(10) EthernetTag(4) [MPLS(3)]. */
    private static void type1(StringBuilder b, byte[] d) {
        appendRd(b, d);
        if (d.length >= RD_LEN + ESI_LEN) {
            appendStringField(b, "esi", formatEsi(d, RD_LEN));
        }
        if (d.length >= RD_LEN + ESI_LEN + ETAG_LEN) {
            appendNumberField(b, "ethernet_tag", readUint32(d, RD_LEN + ESI_LEN));
        }
        int off = RD_LEN + ESI_LEN + ETAG_LEN;
        if (d.length >= off + LABEL_LEN) {
            appendNumberField(b, "mpls_label1", parseMplsLabel(d, off));
        }
    }

    /**
     * Type 2 — RD(8) ESI(10) EthernetTag(4) MACLen(1) MAC(6) IPLen(1) IP(0/4/16)
     * [MPLS1(3)] [MPLS2(3)]. The MAC and IP lengths are expressed in bits.
     */
    private static void type2(StringBuilder b, byte[] d) {
        appendRd(b, d);
        if (d.length >= RD_LEN + ESI_LEN) {
            appendStringField(b, "esi", formatEsi(d, RD_LEN));
        }
        if (d.length < RD_LEN + ESI_LEN + ETAG_LEN + 1) {
            return;
        }
        appendNumberField(b, "ethernet_tag", readUint32(d, RD_LEN + ESI_LEN));

        int off = RD_LEN + ESI_LEN + ETAG_LEN;
        int macBits = d[off] & 0xFF;
        off++;
        int macBytes = macBits / 8;
        if (macBytes > 0 && off + macBytes <= d.length) {
            appendNumberField(b, "mac_len", macBits);
            appendStringField(b, "mac", formatMac(d, off, macBytes));
            off += macBytes;
        }

        if (off >= d.length) {
            return;
        }
        int ipBits = d[off] & 0xFF;
        off++;
        int ipBytes = ipBits / 8;
        if (ipBytes > 0 && off + ipBytes <= d.length) {
            appendNumberField(b, "ip_len", ipBits);
            appendStringField(b, "ip", formatIp(d, off, ipBytes));
            off += ipBytes;
        }

        if (off + LABEL_LEN <= d.length) {
            appendNumberField(b, "mpls_label1", parseMplsLabel(d, off));
            off += LABEL_LEN;
        }
        if (off + LABEL_LEN <= d.length) {
            appendNumberField(b, "mpls_label2", parseMplsLabel(d, off));
        }
    }

    /** Type 3 — RD(8) EthernetTag(4) IPLen(1) OriginatingRouterIP(4/16). */
    private static void type3(StringBuilder b, byte[] d) {
        appendRd(b, d);
        if (d.length < RD_LEN + ETAG_LEN + 1) {
            return;
        }
        appendNumberField(b, "ethernet_tag", readUint32(d, RD_LEN));
        int ipBits = d[RD_LEN + ETAG_LEN] & 0xFF;
        int ipBytes = ipBits / 8;
        int off = RD_LEN + ETAG_LEN + 1;
        if (ipBytes > 0 && off + ipBytes <= d.length) {
            appendNumberField(b, "ip_len", ipBits);
            appendStringField(b, "ip", formatIp(d, off, ipBytes));
        }
    }

    /** Type 4 — RD(8) ESI(10) IPLen(1) OriginatingRouterIP(4/16). */
    private static void type4(StringBuilder b, byte[] d) {
        appendRd(b, d);
        if (d.length >= RD_LEN + ESI_LEN) {
            appendStringField(b, "esi", formatEsi(d, RD_LEN));
        }
        if (d.length < RD_LEN + ESI_LEN + 1) {
            return;
        }
        int ipBits = d[RD_LEN + ESI_LEN] & 0xFF;
        int ipBytes = ipBits / 8;
        int off = RD_LEN + ESI_LEN + 1;
        if (ipBytes > 0 && off + ipBytes <= d.length) {
            appendNumberField(b, "ip_len", ipBits);
            appendStringField(b, "ip", formatIp(d, off, ipBytes));
        }
    }

    /**
     * Type 5 — RD(8) ESI(10) EthernetTag(4) IPPrefixLen(1) IPPrefix(4/16) GatewayIP(4/16)
     * [MPLS(3)]. The IP width is 4 octets when the prefix length is at most 32, otherwise
     * 16 octets.
     */
    private static void type5(StringBuilder b, byte[] d) {
        appendRd(b, d);
        if (d.length >= RD_LEN + ESI_LEN) {
            appendStringField(b, "esi", formatEsi(d, RD_LEN));
        }
        if (d.length < RD_LEN + ESI_LEN + ETAG_LEN + 1) {
            return;
        }
        appendNumberField(b, "ethernet_tag", readUint32(d, RD_LEN + ESI_LEN));
        int prefixLen = d[RD_LEN + ESI_LEN + ETAG_LEN] & 0xFF;
        appendNumberField(b, "prefix_len", prefixLen);

        int off = RD_LEN + ESI_LEN + ETAG_LEN + 1;
        int ipBytes = prefixLen > 32 ? 16 : 4;
        if (off + ipBytes <= d.length) {
            appendStringField(b, "ip", formatIp(d, off, ipBytes));
            off += ipBytes;
        }
        if (off + ipBytes <= d.length) {
            appendStringField(b, "gateway_ip", formatIp(d, off, ipBytes));
            off += ipBytes;
        }
        if (off + LABEL_LEN <= d.length) {
            appendNumberField(b, "mpls_label1", parseMplsLabel(d, off));
        }
    }

    // ------------------------------------------------------------------
    // Sub-value formatting.
    // ------------------------------------------------------------------

    /** Maps a Route Type to its stable mnemonic (RFC 7432 §7, RFC 9136). */
    private static String routeTypeString(int routeType) {
        return switch (routeType) {
            case TYPE_ETHERNET_AUTO_DISCOVERY -> "ethernet_auto_discovery";
            case TYPE_MAC_IP -> "mac_ip";
            case TYPE_INCLUSIVE_MULTICAST -> "inclusive_multicast";
            case TYPE_ETHERNET_SEGMENT -> "ethernet_segment";
            case TYPE_IP_PREFIX -> "ip_prefix";
            default -> "unknown_" + (routeType & 0xFF);
        };
    }

    /**
     * Appends the always-present {@code rd} field, rendering the 8-octet Route
     * Distinguisher (RFC 4364 §4.2) at offset 0.
     */
    private static void appendRd(StringBuilder b, byte[] d) {
        b.append(',');
        appendString(b, "rd", formatRd(d));
    }

    /**
     * Renders an 8-octet Route Distinguisher (RFC 4364 §4.2). Type 0 is
     * {@code 2-byte-asn:4-byte-number}, type 1 is {@code ipv4:2-byte-number}, type 2 is
     * {@code 4-byte-asn:2-byte-number}; anything else (or a short buffer) is reported
     * conservatively rather than throwing.
     */
    private static String formatRd(byte[] d) {
        if (d.length < RD_LEN) {
            return "0:0";
        }
        int rdType = ((d[0] & 0xFF) << 8) | (d[1] & 0xFF);
        return switch (rdType) {
            case 0 -> {
                int admin = ((d[2] & 0xFF) << 8) | (d[3] & 0xFF);
                long assigned = readUint32(d, 4);
                yield admin + ":" + assigned;
            }
            case 1 -> {
                String admin = (d[2] & 0xFF) + "." + (d[3] & 0xFF) + "."
                        + (d[4] & 0xFF) + "." + (d[5] & 0xFF);
                int assigned = ((d[6] & 0xFF) << 8) | (d[7] & 0xFF);
                yield admin + ":" + assigned;
            }
            case 2 -> {
                long admin = readUint32(d, 2);
                int assigned = ((d[6] & 0xFF) << 8) | (d[7] & 0xFF);
                yield admin + ":" + assigned;
            }
            default -> "unknown(" + rdType + ")";
        };
    }

    /** Renders the 10-octet ESI at {@code off} as lowercase colon-separated hex. */
    private static String formatEsi(byte[] d, int off) {
        StringBuilder s = new StringBuilder(ESI_LEN * 3);
        for (int i = 0; i < ESI_LEN; i++) {
            if (i > 0) {
                s.append(':');
            }
            int v = d[off + i] & 0xFF;
            s.append(HEX[v >>> 4]).append(HEX[v & 0x0F]);
        }
        return s.toString();
    }

    /** Renders {@code len} octets at {@code off} as lowercase colon-separated MAC hex. */
    private static String formatMac(byte[] d, int off, int len) {
        StringBuilder s = new StringBuilder(len * 3);
        for (int i = 0; i < len; i++) {
            if (i > 0) {
                s.append(':');
            }
            int v = d[off + i] & 0xFF;
            s.append(HEX[v >>> 4]).append(HEX[v & 0x0F]);
        }
        return s.toString();
    }

    /**
     * Renders {@code len} octets at {@code off} as an IP address via
     * {@link InetAddress#getByAddress(byte[])}; a 4-octet slice yields dotted-decimal
     * IPv4 and a 16-octet slice yields the canonical IPv6 form. Any other length, or an
     * out-of-range slice, falls back to a hex rendering rather than throwing.
     */
    private static String formatIp(byte[] d, int off, int len) {
        if (off < 0 || len < 0 || off + len > d.length) {
            return hex(d);
        }
        byte[] addr = new byte[len];
        System.arraycopy(d, off, addr, 0, len);
        if (len == 4 || len == 16) {
            try {
                return InetAddress.getByAddress(addr).getHostAddress();
            } catch (UnknownHostException ignored) {
                // Unreachable for length 4/16, but degrade gracefully if it ever occurs.
            }
        }
        return hex(addr);
    }

    /** Decodes a 20-bit MPLS label from the 3 octets at {@code off} (RFC 3032). */
    private static long parseMplsLabel(byte[] d, int off) {
        return ((long) (d[off] & 0xFF) << 12)
                | ((long) (d[off + 1] & 0xFF) << 4)
                | ((d[off + 2] & 0xFF) >> 4);
    }

    /** Reads a big-endian unsigned 32-bit integer at {@code off}. */
    private static long readUint32(byte[] d, int off) {
        return ((long) (d[off] & 0xFF) << 24)
                | ((long) (d[off + 1] & 0xFF) << 16)
                | ((long) (d[off + 2] & 0xFF) << 8)
                | (d[off + 3] & 0xFF);
    }

    // ------------------------------------------------------------------
    // Manual JSON emission (matches the in-house StringBuilder style).
    // ------------------------------------------------------------------

    /** Appends {@code "key":value} for an integer value (no leading comma). */
    private static void appendNumber(StringBuilder b, String key, long value) {
        b.append('"').append(key).append("\":").append(value);
    }

    /** Appends {@code "key":"value"} for a string value (no leading comma). */
    private static void appendString(StringBuilder b, String key, String value) {
        b.append('"').append(key).append("\":\"");
        escape(b, value);
        b.append('"');
    }

    /** Appends {@code ,"key":value} for an omit-empty integer (skipped when zero). */
    private static void appendNumberField(StringBuilder b, String key, long value) {
        if (value == 0) {
            return;
        }
        b.append(',');
        appendNumber(b, key, value);
    }

    /** Appends {@code ,"key":"value"} for an omit-empty string (skipped when empty). */
    private static void appendStringField(StringBuilder b, String key, String value) {
        if (value == null || value.isEmpty()) {
            return;
        }
        b.append(',');
        appendString(b, key, value);
    }

    /** Appends {@code value} to {@code b} with the mandatory JSON string escapes. */
    private static void escape(StringBuilder b, String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
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
                        b.append("\\u00")
                                .append(HEX[(c >> 4) & 0x0F])
                                .append(HEX[c & 0x0F]);
                    } else {
                        b.append(c);
                    }
                }
            }
        }
    }

    /** Renders {@code bytes} as a lowercase hex string. */
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
