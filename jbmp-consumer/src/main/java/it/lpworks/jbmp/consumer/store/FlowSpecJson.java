package it.lpworks.jbmp.consumer.store;

/**
 * Builds the structured-JSON representation of a single BGP Flow Specification rule body.
 *
 * <p>This decoder consumes the on-wire rule body (the bytes that follow the NLRI length
 * prefix, including a leading 8-octet Route Distinguisher for the VPN variant) and renders
 * it as a JSON object whose shape mirrors the structured representation stored by the
 * reference collector, so that both systems persist byte-for-byte identical structured data.
 *
 * <h2>JSON shape</h2>
 * <pre>
 * {
 *   "length": &lt;int&gt;,                 // body length in octets
 *   "components": [                     // ordered list of decoded components
 *     {"type": &lt;int&gt;, "type_str": "&lt;name&gt;", "raw": "&lt;hex&gt;"},
 *     ...
 *   ],
 *   "rd": "&lt;text&gt;"                    // present only for the VPN variant
 * }
 * </pre>
 *
 * <p>The {@code rd} field is omitted entirely (omit-empty) for the non-VPN variant, matching
 * the reference. Because the public {@link #toJson(byte[])} entry point is given only the raw
 * bytes and not the SAFI, it decodes the non-VPN layout; the VPN layout (with the leading
 * Route Distinguisher) is available through {@link #toJson(byte[], boolean)}.
 *
 * <h2>Component encoding</h2>
 * <p>A Flow Specification NLRI is an ordered list of components, each introduced by a 1-octet
 * type followed by a type-specific encoding (RFC 8955 §4.2.1):
 * <ul>
 *   <li>Destination Prefix (type 1) and Source Prefix (type 2): a prefix-length octet
 *       followed by {@code ceil(prefixLen / 8)} address octets. The component {@code raw}
 *       is rendered as {@code <hex-of-address-octets>/<prefixLen>} (the type and length
 *       octets are not included in this rendering).</li>
 *   <li>Numeric-match types (3..13 and any other type): a sequence of {@code {operator,
 *       value}} pairs where the operator's two-bit length field (bits 0x30) gives the value
 *       width as {@code 1 << len} and the end-of-list bit (0x80) terminates the sequence
 *       (RFC 8955 §4.2.1.1). The component {@code raw} is the hex of the whole component,
 *       <em>including</em> the leading type octet.</li>
 * </ul>
 *
 * <h2>Robustness</h2>
 * <p>This class never throws and never drops bytes. When the body is shorter than expected or
 * a component cannot be delimited, the remaining bytes are captured as a final component whose
 * {@code raw} carries their hex, so no information is lost.
 *
 * <p>See RFC 8955 (Dissemination of Flow Specification Rules), RFC 9117 (VPN Flow
 * Specification) and RFC 4364 §4.2 (Route Distinguisher). The class is stateless and
 * thread-safe.
 */
public final class FlowSpecJson {

    /** Destination Prefix component (RFC 8955 §4.2.1.2). */
    private static final int TYPE_DST_PREFIX = 1;
    /** Source Prefix component (RFC 8955 §4.2.1.3). */
    private static final int TYPE_SRC_PREFIX = 2;

    /** Length of the Route Distinguisher carried by the VPN variant (RFC 9117). */
    private static final int RD_LEN = 8;

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private FlowSpecJson() {
        throw new AssertionError("No instances");
    }

    /**
     * Renders a non-VPN Flow Specification rule body (SAFI 133) as structured JSON.
     *
     * @param raw the rule body bytes (the bytes after the NLRI length prefix); may be
     *            {@code null} or empty
     * @return the JSON string, or {@code null} when {@code raw} is {@code null} or empty
     */
    public static String toJson(byte[] raw) {
        return toJson(raw, false);
    }

    /**
     * Renders a Flow Specification rule body as structured JSON.
     *
     * @param raw   the rule body bytes (the bytes after the NLRI length prefix, including the
     *              leading 8-octet Route Distinguisher when {@code vpn} is {@code true}); may
     *              be {@code null} or empty
     * @param vpn   {@code true} for the VPN variant (SAFI 134), in which case the leading
     *              8-octet Route Distinguisher is decoded into the {@code rd} field
     * @return the JSON string, or {@code null} when {@code raw} is {@code null} or empty
     */
    public static String toJson(byte[] raw, boolean vpn) {
        if (raw == null || raw.length == 0) {
            return null;
        }

        StringBuilder b = new StringBuilder(64 + raw.length * 3);
        b.append("{\"length\":").append(raw.length);

        int offset = 0;
        String rd = null;
        if (vpn && raw.length >= RD_LEN) {
            rd = formatRd(raw, 0);
            offset = RD_LEN;
        }

        b.append(",\"components\":[");
        appendComponents(b, raw, offset);
        b.append(']');

        if (rd != null) {
            b.append(",\"rd\":\"").append(escape(rd)).append('"');
        }

        b.append('}');
        return b.toString();
    }

    /**
     * Appends the JSON for every component found from {@code offset} to the end of the body,
     * falling back to a single raw component if a component cannot be delimited.
     */
    private static void appendComponents(StringBuilder b, byte[] raw, int offset) {
        boolean first = true;
        int pos = offset;
        while (pos < raw.length) {
            int compStart = pos;
            int type = raw[pos] & 0xFF;
            pos++;

            int end;
            String rawHex;
            try {
                if (type == TYPE_DST_PREFIX || type == TYPE_SRC_PREFIX) {
                    if (pos >= raw.length) {
                        // Truncated: no room for the prefix-length octet; keep the remainder.
                        rawHex = hex(raw, compStart, raw.length);
                        end = raw.length;
                    } else {
                        int prefixLen = raw[pos] & 0xFF;
                        pos++;
                        int prefixBytes = (prefixLen + 7) / 8;
                        int prefixEnd = Math.min(pos + prefixBytes, raw.length);
                        // Prefix rendering excludes the type and prefix-length octets.
                        rawHex = hex(raw, pos, prefixEnd) + "/" + prefixLen;
                        end = prefixEnd;
                    }
                } else {
                    // Numeric op/value pairs terminated by the end-of-list bit (0x80).
                    int p = pos;
                    boolean terminated = false;
                    while (p < raw.length) {
                        int op = raw[p] & 0xFF;
                        p++;
                        int valLen = 1 << ((op >> 4) & 0x03);
                        p = Math.min(p + valLen, raw.length);
                        if ((op & 0x80) != 0) {
                            terminated = true;
                            break;
                        }
                    }
                    end = p;
                    // The numeric rendering includes the leading type octet.
                    rawHex = hex(raw, compStart, end);
                    if (!terminated && end <= compStart + 1) {
                        // No operator octet at all after the type: treat as undecodable tail.
                        rawHex = hex(raw, compStart, raw.length);
                        end = raw.length;
                    }
                }
            } catch (RuntimeException ex) {
                // Defensive: never throw, never drop bytes — keep the remainder verbatim.
                rawHex = hex(raw, compStart, raw.length);
                end = raw.length;
            }

            if (!first) {
                b.append(',');
            }
            first = false;
            b.append("{\"type\":").append(type)
                    .append(",\"type_str\":\"").append(escape(typeString(type))).append('"')
                    .append(",\"raw\":\"").append(escape(rawHex)).append("\"}");

            if (end <= compStart) {
                // Guard against non-progress; emit the remainder and stop.
                break;
            }
            pos = end;
        }
    }

    /** Maps a component type to its canonical short name (RFC 8955 §4.2.1). */
    private static String typeString(int type) {
        return switch (type) {
            case 1 -> "dst_prefix";
            case 2 -> "src_prefix";
            case 3 -> "ip_protocol";
            case 4 -> "port";
            case 5 -> "dst_port";
            case 6 -> "src_port";
            case 7 -> "icmp_type";
            case 8 -> "icmp_code";
            case 9 -> "tcp_flags";
            case 10 -> "packet_len";
            case 11 -> "dscp";
            case 12 -> "fragment";
            case 13 -> "flow_label";
            default -> "unknown_" + type;
        };
    }

    /**
     * Renders the 8-octet Route Distinguisher at {@code at} in its canonical textual form
     * (RFC 4364 §4.2): {@code 2-byte-asn:4-byte-number} (type 0),
     * {@code ipv4:2-byte-number} (type 1), {@code 4-byte-asn:2-byte-number} (type 2),
     * or {@code unknown(<type>)} otherwise.
     */
    private static String formatRd(byte[] raw, int at) {
        int rdType = read16(raw, at);
        return switch (rdType) {
            case 0 -> read16(raw, at + 2) + ":" + read32(raw, at + 4);
            case 1 -> (raw[at + 2] & 0xFF) + "." + (raw[at + 3] & 0xFF) + "."
                    + (raw[at + 4] & 0xFF) + "." + (raw[at + 5] & 0xFF)
                    + ":" + read16(raw, at + 6);
            case 2 -> read32(raw, at + 2) + ":" + read16(raw, at + 6);
            default -> "unknown(" + rdType + ")";
        };
    }

    private static int read16(byte[] raw, int at) {
        return ((raw[at] & 0xFF) << 8) | (raw[at + 1] & 0xFF);
    }

    private static long read32(byte[] raw, int at) {
        return ((long) (raw[at] & 0xFF) << 24)
                | ((long) (raw[at + 1] & 0xFF) << 16)
                | ((long) (raw[at + 2] & 0xFF) << 8)
                | (raw[at + 3] & 0xFF);
    }

    /** Lower-case hex of {@code raw[from, to)}; empty when the range is empty. */
    private static String hex(byte[] raw, int from, int to) {
        if (to <= from) {
            return "";
        }
        char[] out = new char[(to - from) * 2];
        int o = 0;
        for (int i = from; i < to; i++) {
            int v = raw[i] & 0xFF;
            out[o++] = HEX[v >>> 4];
            out[o++] = HEX[v & 0x0F];
        }
        return new String(out);
    }

    /** Minimal JSON string escaping for the values this class emits. */
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
                default -> c < 0x20 ? String.format("\\u%04x", (int) c) : null;
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
        return b == null ? s : b.toString();
    }
}
