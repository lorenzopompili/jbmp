package it.lpworks.jbmp.consumer.store;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.OptionalLong;
import java.util.UUID;

import it.lpworks.jbmp.protocol.bgp.LargeCommunity;
import it.lpworks.jbmp.protocol.io.ByteWriter;
import it.lpworks.jbmp.wire.AsPathSegmentInfo;
import it.lpworks.jbmp.wire.RouteAction;
import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * Encoder for the PostgreSQL <em>binary</em> {@code COPY} stream of the {@code route_monitor}
 * table, carrying the full BGP attribute set in each column's native on-disk representation.
 *
 * <p>Binary {@code COPY} is materially faster to ingest than text: the server consumes each value
 * directly, skipping per-value text parsing, array/JSON tokenising and locale handling. This
 * matters here because the rows are wide (39 columns including arrays and {@code jsonb}). The
 * stored values are identical to those a reference writer produces for the same wire data —
 * {@code cidr}/{@code inet} addresses, {@code int[]} / {@code text[]} / {@code uuid[]} arrays,
 * large communities as {@code global:local1:local2}, extended communities as the hex of their raw
 * bytes, and {@code [{type,asns}]} AS-path segments as {@code jsonb}.
 *
 * <h2>Wire layout (all integers big-endian)</h2>
 * <ul>
 *   <li><b>Header</b>: the 11-byte signature {@code PGCOPY\n\377\r\n\0}, int32 flags (0), int32
 *       header-extension length (0).</li>
 *   <li><b>Row</b>: an int16 field count (39), then per field an int32 byte length ({@code -1} for
 *       SQL {@code NULL}, no bytes following) and that many value bytes.</li>
 *   <li><b>Trailer</b>: an int16 of {@code -1}.</li>
 * </ul>
 *
 * <p>The announce-only scalar attributes are {@code NULL} on a withdraw, and End-of-RIB markers
 * (no NLRI, {@code prefix} is {@code NOT NULL}) are skipped, matching the reference writer. The
 * class is stateless and thread-safe.
 */
public final class RouteMonitorCopy {

    /** Column order of the {@code COPY route_monitor (...)} statement this encoder feeds. */
    static final String COLUMN_LIST =
            "received_at, timestamp, collector_id, router_id, peer_id, action, is_end_of_rib, "
            + "prefix, is_ipv4, origin_as, as_path, as_path_len, next_hop, med, local_pref, origin, "
            + "atomic_agg, aggregator_as, aggregator_ip, communities, large_communities, "
            + "ext_communities, vprn_id, route_target, peer_rd, ls_attrs, is_prepolicy, is_locrib, "
            + "kafka_partition, kafka_offset, path_id, mpls_labels, originator_id, cluster_list, "
            + "as_path_segments, evpn_data, flowspec_data, sr_policy_data, raw_nlri";

    /** Number of fields emitted per row (must match {@link #COLUMN_LIST}). */
    static final int FIELD_COUNT = 39;

    /** The 11-byte binary {@code COPY} signature {@code P G C O P Y \n \377 \r \n \0}. */
    static final byte[] SIGNATURE = {
            (byte) 0x50, (byte) 0x47, (byte) 0x43, (byte) 0x4F, (byte) 0x50, (byte) 0x59,
            (byte) 0x0A, (byte) 0xFF, (byte) 0x0D, (byte) 0x0A, (byte) 0x00
    };

    /** Microseconds between the Unix epoch (1970-01-01) and the PostgreSQL epoch (2000-01-01). */
    private static final long PG_EPOCH_MICROS = 946_684_800L * 1_000_000L;

    // PostgreSQL element type OIDs for the array columns.
    private static final long OID_INT4 = 23;
    private static final long OID_TEXT = 25;
    private static final long OID_UUID = 2950;

    // inet/cidr address family bytes used by the binary representation (not the OS AF_* values).
    private static final int PG_AF_INET = 2;
    private static final int PG_AF_INET6 = 3;

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private RouteMonitorCopy() {
        throw new AssertionError("No instances");
    }

    /**
     * Encodes a batch of route-monitoring events into a complete PostgreSQL binary {@code COPY}
     * stream: header, one row per non End-of-RIB message in iteration order, then the trailer.
     *
     * @param batch the route-monitoring events to encode (never {@code null}; may be empty)
     * @return the freshly allocated binary {@code COPY} byte stream
     */
    public static byte[] encode(List<RouteMonitorMessage> batch) {
        return encode(batch, null, null);
    }

    /**
     * As {@link #encode(List)}, but stamps each row's Kafka provenance ({@code kafka_partition},
     * {@code kafka_offset}). {@code partitions}/{@code offsets} are indexed in lock-step with
     * {@code batch} (so End-of-RIB entries, which are skipped, keep the others aligned); pass
     * {@code null} for both to leave the provenance columns {@code NULL}.
     */
    public static byte[] encode(List<RouteMonitorMessage> batch, int[] partitions, long[] offsets) {
        boolean provenance = partitions != null && offsets != null;
        ByteWriter out = new ByteWriter(Math.max(64, batch.size() * 320));
        out.writeBytes(SIGNATURE);
        out.writeUint32(0L); // flags
        out.writeUint32(0L); // header-extension length
        for (int i = 0; i < batch.size(); i++) {
            RouteMonitorMessage msg = batch.get(i);
            if (msg.endOfRib()) {
                continue;
            }
            writeRow(out, msg, provenance, provenance ? partitions[i] : 0,
                    provenance ? offsets[i] : 0L);
        }
        out.writeUint16(0xFFFF); // trailer: int16 == -1
        return out.toByteArray();
    }

    private static void writeRow(ByteWriter out, RouteMonitorMessage msg, boolean provenance,
            int partition, long offset) {
        boolean announce = msg.action() == RouteAction.ANNOUNCE;
        var h = msg.header();
        out.writeUint16(FIELD_COUNT);

        timestamptz(out, h.receivedAtNanos());                       // received_at
        timestamptz(out, h.timestampNanos());                        // timestamp
        int2(out, h.collectorId());                                  // collector_id
        uuid(out, h.routerId());                                     // router_id
        uuid(out, h.peerId());                                       // peer_id
        int2(out, announce ? 0 : 1);                                 // action
        bool(out, msg.endOfRib());                                   // is_end_of_rib
        cidr(out, msg.prefix(), msg.prefixLength(), msg.ipv4());     // prefix
        bool(out, msg.ipv4());                                       // is_ipv4
        optInt4(out, announce ? msg.originAsn() : OptionalLong.empty()); // origin_as
        intArrayLong(out, msg.asPath());                             // as_path
        if (announce && msg.asPath().length > 0) {
            int2(out, msg.asPath().length);
        } else {
            nul(out);                                                // as_path_len
        }
        inet(out, msg.nextHop());                                    // next_hop
        optInt4(out, announce ? msg.med() : OptionalLong.empty());   // med
        optInt4(out, announce ? msg.localPref() : OptionalLong.empty()); // local_pref
        if (announce) {
            int2(out, msg.origin());
        } else {
            nul(out);                                                // origin
        }
        if (announce) {
            bool(out, msg.atomicAggregate());
        } else {
            nul(out);                                                // atomic_agg
        }
        if (msg.aggregatorAsn().isPresent() && msg.aggregatorAsn().getAsLong() > 0) {
            int4(out, (int) msg.aggregatorAsn().getAsLong());
        } else {
            nul(out);                                                // aggregator_as
        }
        inet(out, msg.aggregatorAddress());                          // aggregator_ip
        intArrayInt(out, msg.communities());                         // communities
        textArray(out, largeCommunityStrings(msg.largeCommunities()));   // large_communities
        textArray(out, extCommunityHex(msg.extendedCommunities()));  // ext_communities
        nul(out);                                                    // vprn_id (not produced)
        textArray(out, msg.routeTargets());                          // route_target
        textOrNull(out, msg.peerRd());                               // peer_rd
        jsonb(out, BgpLsJson.toJson(msg.linkState()));               // ls_attrs (BGP-LS attribute)
        bool(out, msg.prePolicy());                                  // is_prepolicy
        bool(out, msg.locRib());                                     // is_locrib
        if (provenance) {
            int2(out, partition);                                    // kafka_partition
            int8(out, offset);                                       // kafka_offset
        } else {
            nul(out);
            nul(out);
        }
        if (msg.pathId().isPresent() && msg.pathId().getAsLong() > 0) {
            int4(out, (int) msg.pathId().getAsLong());
        } else {
            nul(out);                                                // path_id
        }
        intArrayLong(out, msg.mplsLabels());                         // mpls_labels
        if (msg.originatorId().isPresent()) {
            uuid(out, msg.originatorId().get());
        } else {
            nul(out);                                                // originator_id
        }
        uuidArray(out, msg.clusterList());                           // cluster_list
        jsonb(out, asPathSegmentsJson(msg.asPathSegments()));        // as_path_segments
        jsonb(out, evpnJsonArray(msg.evpn()));                       // evpn_data
        jsonb(out, flowSpecJsonArray(msg.flowSpec()));               // flowspec_data
        jsonb(out, SrPolicyJson.toJson(msg.srPolicy()));             // sr_policy_data
        jsonbRaw(out, msg.rawNlri());                                // raw_nlri
    }

    // ------------------------------------------------------------------
    // Scalar field writers (int32 length prefix + value bytes; -1 == NULL).
    // ------------------------------------------------------------------

    private static void nul(ByteWriter out) {
        out.writeUint32(0xFFFFFFFFL);
    }

    private static void int2(ByteWriter out, int value) {
        out.writeUint32(2L);
        out.writeUint16(value & 0xFFFF);
    }

    private static void int4(ByteWriter out, int value) {
        out.writeUint32(4L);
        out.writeUint32(Integer.toUnsignedLong(value));
    }

    private static void int8(ByteWriter out, long value) {
        out.writeUint32(8L);
        out.writeUint64(value);
    }

    private static void optInt4(ByteWriter out, OptionalLong value) {
        if (value.isPresent()) {
            int4(out, (int) value.getAsLong());
        } else {
            nul(out);
        }
    }

    private static void bool(ByteWriter out, boolean value) {
        out.writeUint32(1L);
        out.writeUint8(value ? 1 : 0);
    }

    private static void timestamptz(ByteWriter out, long nanos) {
        out.writeUint32(8L);
        out.writeUint64(nanos / 1000L - PG_EPOCH_MICROS);
    }

    private static void uuid(ByteWriter out, UUID value) {
        out.writeUint32(16L);
        out.writeUint64(value.getMostSignificantBits());
        out.writeUint64(value.getLeastSignificantBits());
    }

    private static void textOrNull(ByteWriter out, String value) {
        if (value == null || value.isBlank()) {
            nul(out);
        } else {
            byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
            out.writeUint32(utf8.length);
            out.writeBytes(utf8);
        }
    }

    /** Writes a {@code jsonb} value (version byte {@code 0x01} + UTF-8 JSON), or NULL if absent. */
    private static void jsonb(ByteWriter out, String json) {
        if (json == null) {
            nul(out);
            return;
        }
        byte[] utf8 = json.getBytes(StandardCharsets.UTF_8);
        out.writeUint32(utf8.length + 1L);
        out.writeUint8(1); // jsonb format version
        out.writeBytes(utf8);
    }

    /** Wraps opaque NLRI/attribute bytes as {@code {"raw":"<hex>","len":N}} jsonb, or NULL. */
    private static void jsonbRaw(ByteWriter out, byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            nul(out);
        } else {
            jsonb(out, "{\"raw\":\"" + hex(bytes) + "\",\"len\":" + bytes.length + "}");
        }
    }

    /**
     * Decodes an EVPN route into the {@code jsonb} array form (one route object). The 1-octet
     * route type is the leading byte (stamped by the collector); the type-specific body follows.
     */
    private static String evpnJsonArray(byte[] evpn) {
        if (evpn == null || evpn.length == 0) {
            return null;
        }
        int routeType = evpn[0] & 0xFF;
        byte[] raw = java.util.Arrays.copyOfRange(evpn, 1, evpn.length);
        String obj = EvpnJson.toJson(routeType, raw);
        return obj == null ? null : "[" + obj + "]";
    }

    /** Decodes a FlowSpec rule into the {@code jsonb} array form (one rule object). */
    private static String flowSpecJsonArray(byte[] flowSpec) {
        if (flowSpec == null || flowSpec.length == 0) {
            return null;
        }
        String obj = FlowSpecJson.toJson(flowSpec);
        return obj == null ? null : "[" + obj + "]";
    }

    /** Writes a {@code cidr}: family / netmask bits / is_cidr=1 / address-byte-count / address. */
    private static void cidr(ByteWriter out, byte[] prefix, int len, boolean ipv4) {
        int nb = ipv4 ? 4 : 16;
        out.writeUint32(4L + nb);
        out.writeUint8(ipv4 ? PG_AF_INET : PG_AF_INET6);
        out.writeUint8(len & 0xFF);
        out.writeUint8(1); // is_cidr
        out.writeUint8(nb);
        out.writeBytes(fit(prefix, nb));
    }

    /** Writes an {@code inet} (host address, full mask, is_cidr=0), or NULL if absent. */
    private static void inet(ByteWriter out, byte[] addr) {
        if (addr == null || addr.length == 0) {
            nul(out);
            return;
        }
        int nb = addr.length == 16 ? 16 : 4;
        out.writeUint32(4L + nb);
        out.writeUint8(nb == 4 ? PG_AF_INET : PG_AF_INET6);
        out.writeUint8(nb * 8); // full host mask
        out.writeUint8(0); // is_cidr = false (inet)
        out.writeUint8(nb);
        out.writeBytes(fit(addr, nb));
    }

    // ------------------------------------------------------------------
    // Array field writers (PostgreSQL 1-dimensional array binary layout).
    // ------------------------------------------------------------------

    private static void intArrayLong(ByteWriter out, long[] values) {
        if (values == null || values.length == 0) {
            nul(out);
            return;
        }
        ByteWriter body = arrayHeader(values.length, OID_INT4);
        for (long v : values) {
            body.writeUint32(4L);
            body.writeUint32(v & 0xFFFFFFFFL);
        }
        field(out, body);
    }

    private static void intArrayInt(ByteWriter out, int[] values) {
        if (values == null || values.length == 0) {
            nul(out);
            return;
        }
        ByteWriter body = arrayHeader(values.length, OID_INT4);
        for (int v : values) {
            body.writeUint32(4L);
            body.writeUint32(Integer.toUnsignedLong(v));
        }
        field(out, body);
    }

    private static void textArray(ByteWriter out, List<String> items) {
        if (items == null || items.isEmpty()) {
            nul(out);
            return;
        }
        ByteWriter body = arrayHeader(items.size(), OID_TEXT);
        for (String s : items) {
            byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
            body.writeUint32(utf8.length);
            body.writeBytes(utf8);
        }
        field(out, body);
    }

    private static void uuidArray(ByteWriter out, List<UUID> uuids) {
        if (uuids == null || uuids.isEmpty()) {
            nul(out);
            return;
        }
        ByteWriter body = arrayHeader(uuids.size(), OID_UUID);
        for (UUID u : uuids) {
            body.writeUint32(16L);
            body.writeUint64(u.getMostSignificantBits());
            body.writeUint64(u.getLeastSignificantBits());
        }
        field(out, body);
    }

    /** Starts a 1-dimensional, non-null array body (ndim, hasnull, elem OID, length, lower-bound). */
    private static ByteWriter arrayHeader(int count, long elemOid) {
        ByteWriter body = new ByteWriter(32 + count * 8);
        body.writeUint32(1L);        // ndim
        body.writeUint32(0L);        // hasnull
        body.writeUint32(elemOid);   // element type OID
        body.writeUint32(count);     // dimension length
        body.writeUint32(1L);        // lower bound
        return body;
    }

    /** Emits a built field body as an int32 length prefix followed by the bytes. */
    private static void field(ByteWriter out, ByteWriter body) {
        byte[] bytes = body.toByteArray();
        out.writeUint32(bytes.length);
        out.writeBytes(bytes);
    }

    // ------------------------------------------------------------------
    // Value derivation (mirrors the reference textual encodings).
    // ------------------------------------------------------------------

    private static List<String> largeCommunityStrings(List<LargeCommunity> lcs) {
        if (lcs == null || lcs.isEmpty()) {
            return List.of();
        }
        return lcs.stream()
                .map(lc -> lc.globalAdministrator() + ":" + lc.localData1() + ":" + lc.localData2())
                .toList();
    }

    private static List<String> extCommunityHex(List<byte[]> ecs) {
        if (ecs == null || ecs.isEmpty()) {
            return List.of();
        }
        return ecs.stream().map(RouteMonitorCopy::hex).toList();
    }

    private static String asPathSegmentsJson(List<AsPathSegmentInfo> segs) {
        if (segs == null || segs.isEmpty()) {
            return null;
        }
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < segs.size(); i++) {
            if (i > 0) {
                b.append(',');
            }
            AsPathSegmentInfo s = segs.get(i);
            b.append("{\"type\":").append(s.segmentType()).append(",\"asns\":[");
            long[] asns = s.asns();
            for (int j = 0; j < asns.length; j++) {
                if (j > 0) {
                    b.append(',');
                }
                b.append(asns[j]);
            }
            b.append("]}");
        }
        return b.append(']').toString();
    }

    /** Returns {@code src} fitted to exactly {@code width} bytes (truncated or zero-padded). */
    private static byte[] fit(byte[] src, int width) {
        if (src != null && src.length == width) {
            return src;
        }
        byte[] out = new byte[width];
        if (src != null) {
            System.arraycopy(src, 0, out, 0, Math.min(src.length, width));
        }
        return out;
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
