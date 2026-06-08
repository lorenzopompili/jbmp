package it.lpworks.jbmp.wire;

import it.lpworks.jbmp.protocol.bgp.LargeCommunity;
import it.lpworks.jbmp.protocol.io.ByteReader;
import it.lpworks.jbmp.protocol.io.ByteWriter;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.UUID;

/**
 * The Kafka wire codec for the enriched message DTOs in this package.
 *
 * <p>The codec is a stateless collection of static {@code encodeX}/{@code decodeX} methods,
 * one pair per message type ({@link RouteMonitorMessage}, {@link PeerEventMessage},
 * {@link StatsReportMessage}, {@link RouteMirrorMessage}). Encoding produces a
 * self-contained {@code byte[]} suitable for use as a Kafka record value; decoding is its
 * exact inverse for any value produced by the same or an older codec version.
 *
 * <h2>Wire conventions</h2>
 * <ul>
 *   <li><b>Version.</b> The first byte of every message is a {@linkplain #FORMAT_VERSION
 *       format-version constant} (currently {@value #FORMAT_VERSION}). Decoders reject a
 *       version they do not understand.</li>
 *   <li><b>Endianness.</b> All multi-byte integers are big-endian (network byte order),
 *       matching BMP (RFC 7854) and BGP (RFC 4271). Fixed-width scalars are written
 *       directly.</li>
 *   <li><b>UUID.</b> Encoded as 16 bytes: the most-significant 64 bits followed by the
 *       least-significant 64 bits (RFC 4122 big-endian layout).</li>
 *   <li><b>Variable-length fields.</b> Fields known to stay below 64&nbsp;KiB carry a
 *       {@code uint16} length prefix (prefix, next hop, addresses, identifiers, text,
 *       per-element community/AS-path data, route-target strings). Potentially large
 *       blobs carry a {@code uint32} length prefix (EVPN, Flow Spec, SR Policy, BGP-LS,
 *       raw NLRI, and the sent/received OPEN messages).</li>
 *   <li><b>Optionals.</b> A 1-byte present flag ({@code 0}=absent, {@code 1}=present)
 *       precedes the value, which is written only when present.</li>
 *   <li><b>Lists and arrays.</b> A {@code uint16} element count precedes the elements.</li>
 *   <li><b>Forward compatibility (append-only).</b> New fields are only ever appended.
 *       Decoders read trailing fields through tolerance helpers that return a default when
 *       the buffer is exhausted, so a value written by an older (shorter) encoder decodes
 *       cleanly with newer fields defaulted to absent/empty.</li>
 * </ul>
 *
 * <h2>{@link RouteMonitorMessage} byte layout</h2>
 * <p>In encode order (offsets are relative; {@code u8}/{@code u16}/{@code u32}/{@code u64}
 * denote unsigned widths):
 * <pre>
 *   u8   format version (== 1)
 *   --- MessageHeader ---
 *   u64  timestampNanos
 *   u64  receivedAtNanos
 *   u32  collectorId
 *   16B  routerId  (mostSigBits u64, leastSigBits u64)
 *   16B  peerId    (mostSigBits u64, leastSigBits u64)
 *   --- flags / discriminators ---
 *   u8   action            (0=ANNOUNCE, 1=WITHDRAW)
 *   u8   bit-flags: bit0 prePolicy, bit1 locRib, bit2 ipv4, bit3 endOfRib,
 *                   bit4 addPath, bit5 atomicAggregate
 *   --- prefix ---
 *   u16  prefix length-prefix, then prefix bytes
 *   u16  prefixLength (bit count)
 *   --- optionals (each: u8 present flag, then value if present) ---
 *   opt  pathId       (u8 flag, then u64 if present)
 *   opt  originAsn    (u8 flag, then u32 ASN if present, RFC 6793)
 *   --- AS path (ASNs are 32-bit, RFC 6793) ---
 *   u16  asPath ASN count, then that many u32 ASNs
 *   u16  asPathSegments count, then per segment: u8 segmentType,
 *                   u16 ASN count, that many u32 ASNs
 *   --- next hop ---
 *   u16  nextHop length-prefix, then next-hop bytes
 *   --- more optionals ---
 *   opt  med          (u8 flag, then u64 if present)
 *   opt  localPref    (u8 flag, then u64 if present)
 *   --- origin / aggregator ---
 *   s8   origin  (signed byte: 0=IGP,1=EGP,2=INCOMPLETE,-1=absent)
 *   opt  aggregatorAsn  (u8 flag, then u32 ASN if present, RFC 6793)
 *   u16  aggregatorAddress length-prefix, then bytes
 *   --- communities ---
 *   u16  communities count, then that many u32 community values
 *   u16  largeCommunities count, then per entry 3 x u32
 *                   (globalAdministrator, localData1, localData2)
 *   u16  extendedCommunities count, then per entry u16-prefixed bytes
 *   --- route reflection ---
 *   opt  originatorId  (u8 present flag, then 16-byte UUID if present)
 *   u16  clusterList count, then that many 16-byte UUIDs
 *   --- VPN / RD ---
 *   u16  peerRd UTF-8 length-prefix, then bytes
 *   u64  vprnId
 *   u16  routeTargets count, then per entry u16-prefixed UTF-8 string
 *   u16  mplsLabels count, then that many u64 labels
 *   --- opaque NLRI blobs (presence bitmask + only the present payloads) ---
 *   u8   blob presence bitmask: bit0 evpn, bit1 flowSpec, bit2 srPolicy,
 *                   bit3 linkState, bit4 rawNlri; a bit is set iff that blob is non-empty
 *   then, for each SET bit in the bit0..bit4 order above:
 *        u32 length-prefix, then that blob's bytes
 *        (nothing is written for an empty/absent blob)
 * </pre>
 * When every blob is empty the whole region is a single {@code 0x00} byte. Any future field
 * is appended after the blob region; a decoder that reaches end-of-buffer before reading the
 * bitmask treats every blob as absent (empty), and any later field yields its default.
 *
 * <p>This class is not instantiable.
 */
public final class WireCodec {

    /** The current wire format version, written as the first byte of every message. */
    public static final byte FORMAT_VERSION = 2;

    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final long[] EMPTY_LONGS = new long[0];
    private static final int[] EMPTY_INTS = new int[0];
    private static final long MAX_UINT32 = 0xFFFFFFFFL;

    // RouteMonitorMessage extended-family blob presence-bitmask bit positions. A bit is set
    // when the corresponding blob is non-empty; the blobs follow the bitmask, in this order.
    private static final int BLOB_EVPN = 1;
    private static final int BLOB_FLOW_SPEC = 1 << 1;
    private static final int BLOB_SR_POLICY = 1 << 2;
    private static final int BLOB_LINK_STATE = 1 << 3;
    private static final int BLOB_RAW_NLRI = 1 << 4;

    // RouteMonitorMessage flag-byte bit positions.
    private static final int FLAG_PRE_POLICY = 1;
    private static final int FLAG_LOC_RIB = 1 << 1;
    private static final int FLAG_IPV4 = 1 << 2;
    private static final int FLAG_END_OF_RIB = 1 << 3;
    private static final int FLAG_ADD_PATH = 1 << 4;
    private static final int FLAG_ATOMIC_AGGREGATE = 1 << 5;

    // PeerEventMessage flag-byte bit positions.
    private static final int PE_FLAG_PRE_POLICY = 1;
    private static final int PE_FLAG_IPV4 = 1 << 1;
    private static final int PE_FLAG_LOC_RIB = 1 << 2;

    private WireCodec() {
        throw new AssertionError("No instances");
    }

    // ------------------------------------------------------------------
    // RouteMonitorMessage
    // ------------------------------------------------------------------

    /**
     * Encodes a {@link RouteMonitorMessage} to its self-contained wire form.
     *
     * @param msg the message to encode (never {@code null})
     * @return a freshly allocated byte array
     */
    public static byte[] encodeRouteMonitor(RouteMonitorMessage msg) {
        ByteWriter w = new ByteWriter(256);
        w.writeByte(FORMAT_VERSION);
        writeHeader(w, msg.header());

        w.writeUint8(msg.action() == RouteAction.WITHDRAW ? 1 : 0);
        int flags = 0;
        if (msg.prePolicy()) flags |= FLAG_PRE_POLICY;
        if (msg.locRib()) flags |= FLAG_LOC_RIB;
        if (msg.ipv4()) flags |= FLAG_IPV4;
        if (msg.endOfRib()) flags |= FLAG_END_OF_RIB;
        if (msg.addPath()) flags |= FLAG_ADD_PATH;
        if (msg.atomicAggregate()) flags |= FLAG_ATOMIC_AGGREGATE;
        w.writeUint8(flags);

        w.writeBytesU16(msg.prefix());
        w.writeUint16(msg.prefixLength());

        writeOptLong(w, msg.pathId());
        writeOptAsn(w, msg.originAsn());

        writeAsnArray(w, msg.asPath());

        List<AsPathSegmentInfo> segments = msg.asPathSegments();
        w.writeUint16(segments.size());
        for (AsPathSegmentInfo seg : segments) {
            w.writeUint8(seg.segmentType() & 0xFF);
            writeAsnArray(w, seg.asns());
        }

        w.writeBytesU16(msg.nextHop());

        writeOptLong(w, msg.med());
        writeOptLong(w, msg.localPref());

        w.writeByte(msg.origin()); // signed byte: -1 => 0xFF
        writeOptAsn(w, msg.aggregatorAsn());
        w.writeBytesU16(msg.aggregatorAddress());

        int[] communities = msg.communities();
        w.writeUint16(communities.length);
        for (int c : communities) {
            w.writeUint32(c & MAX_UINT32);
        }

        List<LargeCommunity> large = msg.largeCommunities();
        w.writeUint16(large.size());
        for (LargeCommunity lc : large) {
            w.writeUint32(lc.globalAdministrator());
            w.writeUint32(lc.localData1());
            w.writeUint32(lc.localData2());
        }

        List<byte[]> extended = msg.extendedCommunities();
        w.writeUint16(extended.size());
        for (byte[] ec : extended) {
            w.writeBytesU16(ec);
        }

        Optional<UUID> originatorId = msg.originatorId();
        if (originatorId.isPresent()) {
            w.writeUint8(1);
            writeUuid(w, originatorId.get());
        } else {
            w.writeUint8(0);
        }

        List<UUID> clusterList = msg.clusterList();
        w.writeUint16(clusterList.size());
        for (UUID u : clusterList) {
            writeUuid(w, u);
        }

        writeStringU16(w, msg.peerRd());
        w.writeUint64(msg.vprnId());

        List<String> routeTargets = msg.routeTargets();
        w.writeUint16(routeTargets.size());
        for (String rt : routeTargets) {
            writeStringU16(w, rt);
        }

        writeLongArray(w, msg.mplsLabels());

        // Extended-family blobs: a single presence bitmask, then a u32-prefixed payload for
        // each set bit in EVPN, Flow Spec, SR Policy, BGP-LS, raw-NLRI order. Empty blobs
        // (the common case) cost only their bit and no length prefix at all.
        byte[] evpn = msg.evpn();
        byte[] flowSpec = msg.flowSpec();
        byte[] srPolicy = msg.srPolicy();
        byte[] linkState = msg.linkState();
        byte[] rawNlri = msg.rawNlri();
        int blobMask = 0;
        if (evpn.length != 0) blobMask |= BLOB_EVPN;
        if (flowSpec.length != 0) blobMask |= BLOB_FLOW_SPEC;
        if (srPolicy.length != 0) blobMask |= BLOB_SR_POLICY;
        if (linkState.length != 0) blobMask |= BLOB_LINK_STATE;
        if (rawNlri.length != 0) blobMask |= BLOB_RAW_NLRI;
        w.writeUint8(blobMask);
        if ((blobMask & BLOB_EVPN) != 0) w.writeBytesU32(evpn);
        if ((blobMask & BLOB_FLOW_SPEC) != 0) w.writeBytesU32(flowSpec);
        if ((blobMask & BLOB_SR_POLICY) != 0) w.writeBytesU32(srPolicy);
        if ((blobMask & BLOB_LINK_STATE) != 0) w.writeBytesU32(linkState);
        if ((blobMask & BLOB_RAW_NLRI) != 0) w.writeBytesU32(rawNlri);

        return w.toByteArray();
    }

    /**
     * Decodes a {@link RouteMonitorMessage} produced by {@link #encodeRouteMonitor}.
     *
     * <p>Trailing fields introduced by a newer encoder are read with end-of-buffer
     * tolerance; reaching the end early yields their defaults.
     *
     * @param bytes the wire bytes (never {@code null})
     * @return the decoded message
     * @throws IllegalArgumentException if the format version is unsupported
     */
    public static RouteMonitorMessage decodeRouteMonitor(byte[] bytes) {
        ByteReader r = new ByteReader(bytes);
        checkVersion(r);
        MessageHeader header = readHeader(r);

        RouteAction action = r.readUint8() == 1 ? RouteAction.WITHDRAW : RouteAction.ANNOUNCE;
        int flags = r.readUint8();
        boolean prePolicy = (flags & FLAG_PRE_POLICY) != 0;
        boolean locRib = (flags & FLAG_LOC_RIB) != 0;
        boolean ipv4 = (flags & FLAG_IPV4) != 0;
        boolean endOfRib = (flags & FLAG_END_OF_RIB) != 0;
        boolean addPath = (flags & FLAG_ADD_PATH) != 0;
        boolean atomicAggregate = (flags & FLAG_ATOMIC_AGGREGATE) != 0;

        byte[] prefix = readBytesU16(r);
        int prefixLength = r.readUint16();

        OptionalLong pathId = readOptLong(r);
        OptionalLong originAsn = readOptAsn(r);

        long[] asPath = readAsnArray(r);

        int segCount = r.readUint16();
        List<AsPathSegmentInfo> segments = new ArrayList<>(segCount);
        for (int i = 0; i < segCount; i++) {
            int segType = r.readUint8();
            long[] asns = readAsnArray(r);
            segments.add(new AsPathSegmentInfo(segType, asns));
        }

        byte[] nextHop = readBytesU16(r);

        OptionalLong med = readOptLong(r);
        OptionalLong localPref = readOptLong(r);

        int origin = r.readByte(); // signed byte: 0xFF => -1
        OptionalLong aggregatorAsn = readOptAsn(r);
        byte[] aggregatorAddress = readBytesU16(r);

        int commCount = r.readUint16();
        int[] communities = commCount == 0 ? EMPTY_INTS : new int[commCount];
        for (int i = 0; i < commCount; i++) {
            communities[i] = (int) r.readUint32();
        }

        int largeCount = r.readUint16();
        List<LargeCommunity> large = new ArrayList<>(largeCount);
        for (int i = 0; i < largeCount; i++) {
            long ga = r.readUint32();
            long ld1 = r.readUint32();
            long ld2 = r.readUint32();
            large.add(new LargeCommunity(ga, ld1, ld2));
        }

        int extCount = r.readUint16();
        List<byte[]> extended = new ArrayList<>(extCount);
        for (int i = 0; i < extCount; i++) {
            extended.add(readBytesU16(r));
        }

        Optional<UUID> originatorId =
                r.readUint8() == 1 ? Optional.of(readUuid(r)) : Optional.empty();

        int clusterCount = r.readUint16();
        List<UUID> clusterList = new ArrayList<>(clusterCount);
        for (int i = 0; i < clusterCount; i++) {
            clusterList.add(readUuid(r));
        }

        String peerRd = readStringU16(r);
        long vprnId = r.readUint64();

        int rtCount = r.readUint16();
        List<String> routeTargets = new ArrayList<>(rtCount);
        for (int i = 0; i < rtCount; i++) {
            routeTargets.add(readStringU16(r));
        }

        long[] mplsLabels = readLongArray(r);

        // Extended-family blobs: read the presence bitmask, then a u32-prefixed payload for
        // each set bit (same order as encode). Absent bits yield empty arrays. The bitmask
        // is the last currently-defined field; an older/shorter encoder that omits it (no
        // readable byte remains) decodes cleanly with every blob defaulted to empty.
        int blobMask = r.isReadable(1) ? r.readUint8() : 0;
        byte[] evpn = (blobMask & BLOB_EVPN) != 0 ? readBytesU32(r) : EMPTY_BYTES;
        byte[] flowSpec = (blobMask & BLOB_FLOW_SPEC) != 0 ? readBytesU32(r) : EMPTY_BYTES;
        byte[] srPolicy = (blobMask & BLOB_SR_POLICY) != 0 ? readBytesU32(r) : EMPTY_BYTES;
        byte[] linkState = (blobMask & BLOB_LINK_STATE) != 0 ? readBytesU32(r) : EMPTY_BYTES;
        byte[] rawNlri = (blobMask & BLOB_RAW_NLRI) != 0 ? readBytesU32(r) : EMPTY_BYTES;

        return new RouteMonitorMessage(
                header, action, prePolicy, locRib, ipv4, endOfRib, addPath,
                prefix, prefixLength, pathId, originAsn, asPath, segments, nextHop,
                med, localPref, origin, atomicAggregate, aggregatorAsn, aggregatorAddress,
                communities, large, extended, originatorId, clusterList, peerRd, vprnId,
                routeTargets, mplsLabels, evpn, flowSpec, srPolicy, linkState, rawNlri);
    }

    // ------------------------------------------------------------------
    // PeerEventMessage
    // ------------------------------------------------------------------

    /**
     * Encodes a {@link PeerEventMessage} to its self-contained wire form.
     *
     * @param msg the message to encode (never {@code null})
     * @return a freshly allocated byte array
     */
    public static byte[] encodePeerEvent(PeerEventMessage msg) {
        ByteWriter w = new ByteWriter(128);
        w.writeByte(FORMAT_VERSION);
        writeHeader(w, msg.header());

        w.writeUint8(msg.eventType() == PeerEventType.DOWN ? 1 : 0);
        int flags = 0;
        if (msg.prePolicy()) flags |= PE_FLAG_PRE_POLICY;
        if (msg.ipv4()) flags |= PE_FLAG_IPV4;
        if (msg.locRib()) flags |= PE_FLAG_LOC_RIB;
        w.writeUint8(flags);

        w.writeBytesU16(msg.remoteIp());
        w.writeUint64(msg.remoteAsn());
        w.writeBytesU16(msg.remoteBgpId());
        w.writeBytesU16(msg.localIp());
        w.writeUint64(msg.localAsn());
        w.writeBytesU16(msg.localBgpId());
        w.writeUint16(msg.remotePort());
        w.writeUint16(msg.localPort());
        writeStringU16(w, msg.peerRd());
        w.writeUint16(msg.bmpReason());
        w.writeUint16(msg.bgpErrorCode());
        w.writeUint16(msg.bgpErrorSubcode());
        writeStringU16(w, msg.errorText());
        w.writeBytesU32(msg.sentOpen());
        w.writeBytesU32(msg.receivedOpen());
        writeStringU16(w, msg.infoData());

        return w.toByteArray();
    }

    /**
     * Decodes a {@link PeerEventMessage} produced by {@link #encodePeerEvent}.
     *
     * @param bytes the wire bytes (never {@code null})
     * @return the decoded message
     * @throws IllegalArgumentException if the format version is unsupported
     */
    public static PeerEventMessage decodePeerEvent(byte[] bytes) {
        ByteReader r = new ByteReader(bytes);
        checkVersion(r);
        MessageHeader header = readHeader(r);

        PeerEventType eventType = r.readUint8() == 1 ? PeerEventType.DOWN : PeerEventType.UP;
        int flags = r.readUint8();
        boolean prePolicy = (flags & PE_FLAG_PRE_POLICY) != 0;
        boolean ipv4 = (flags & PE_FLAG_IPV4) != 0;
        boolean locRib = (flags & PE_FLAG_LOC_RIB) != 0;

        byte[] remoteIp = readBytesU16(r);
        long remoteAsn = r.readUint64();
        byte[] remoteBgpId = readBytesU16(r);
        byte[] localIp = readBytesU16(r);
        long localAsn = r.readUint64();
        byte[] localBgpId = readBytesU16(r);
        int remotePort = r.readUint16();
        int localPort = r.readUint16();
        String peerRd = readStringU16(r);
        int bmpReason = r.readUint16();
        int bgpErrorCode = r.readUint16();
        int bgpErrorSubcode = r.readUint16();
        String errorText = readStringU16(r);
        byte[] sentOpen = readBytesU32(r);
        byte[] receivedOpen = readBytesU32(r);
        // infoData is the last currently-defined field; tolerate truncation here and beyond.
        String infoData = readStringU16Tolerant(r);

        return new PeerEventMessage(
                header, eventType, remoteIp, remoteAsn, remoteBgpId, localIp, localAsn,
                localBgpId, remotePort, localPort, peerRd, prePolicy, ipv4, locRib,
                bmpReason, bgpErrorCode, bgpErrorSubcode, errorText, sentOpen, receivedOpen,
                infoData);
    }

    // ------------------------------------------------------------------
    // StatsReportMessage
    // ------------------------------------------------------------------

    /**
     * Encodes a {@link StatsReportMessage} to its self-contained wire form. Counters are
     * emitted in ascending Stat-Type order for a deterministic image.
     *
     * @param msg the message to encode (never {@code null})
     * @return a freshly allocated byte array
     */
    public static byte[] encodeStatsReport(StatsReportMessage msg) {
        ByteWriter w = new ByteWriter(64);
        w.writeByte(FORMAT_VERSION);
        writeHeader(w, msg.header());

        var counters = msg.counters(); // already a sorted, unmodifiable map
        w.writeUint16(counters.size());
        for (Map.Entry<Integer, Long> e : counters.entrySet()) {
            w.writeUint16(e.getKey() & 0xFFFF);
            w.writeUint64(e.getValue());
        }
        return w.toByteArray();
    }

    /**
     * Decodes a {@link StatsReportMessage} produced by {@link #encodeStatsReport}.
     *
     * @param bytes the wire bytes (never {@code null})
     * @return the decoded message
     * @throws IllegalArgumentException if the format version is unsupported
     */
    public static StatsReportMessage decodeStatsReport(byte[] bytes) {
        ByteReader r = new ByteReader(bytes);
        checkVersion(r);
        MessageHeader header = readHeader(r);

        TreeMap<Integer, Long> counters = new TreeMap<>();
        int count = r.isReadable(2) ? r.readUint16() : 0;
        for (int i = 0; i < count; i++) {
            int statType = r.readUint16();
            long value = r.readUint64();
            counters.put(statType, value);
        }
        return new StatsReportMessage(header, counters);
    }

    // ------------------------------------------------------------------
    // RouteMirrorMessage
    // ------------------------------------------------------------------

    /**
     * Encodes a {@link RouteMirrorMessage} to its self-contained wire form.
     *
     * @param msg the message to encode (never {@code null})
     * @return a freshly allocated byte array
     */
    public static byte[] encodeRouteMirror(RouteMirrorMessage msg) {
        ByteWriter w = new ByteWriter(64);
        w.writeByte(FORMAT_VERSION);
        writeHeader(w, msg.header());

        w.writeBytesU32(msg.mirroredMessage());

        OptionalInt info = msg.informationCode();
        if (info.isPresent()) {
            w.writeUint8(1);
            w.writeUint16(info.getAsInt() & 0xFFFF);
        } else {
            w.writeUint8(0);
        }
        return w.toByteArray();
    }

    /**
     * Decodes a {@link RouteMirrorMessage} produced by {@link #encodeRouteMirror}.
     *
     * @param bytes the wire bytes (never {@code null})
     * @return the decoded message
     * @throws IllegalArgumentException if the format version is unsupported
     */
    public static RouteMirrorMessage decodeRouteMirror(byte[] bytes) {
        ByteReader r = new ByteReader(bytes);
        checkVersion(r);
        MessageHeader header = readHeader(r);

        byte[] mirrored = readBytesU32(r);
        OptionalInt info;
        if (r.isReadable(1) && r.readUint8() == 1) {
            info = OptionalInt.of(r.readUint16());
        } else {
            info = OptionalInt.empty();
        }
        return new RouteMirrorMessage(header, mirrored, info);
    }

    // ------------------------------------------------------------------
    // Shared primitives
    // ------------------------------------------------------------------

    private static void checkVersion(ByteReader r) {
        int version = r.readUint8();
        if (version != FORMAT_VERSION) {
            throw new IllegalArgumentException(
                    "Unsupported wire format version: " + version
                            + " (expected " + FORMAT_VERSION + ")");
        }
    }

    private static void writeHeader(ByteWriter w, MessageHeader h) {
        w.writeUint64(h.timestampNanos());
        w.writeUint64(h.receivedAtNanos());
        w.writeUint32(h.collectorId() & MAX_UINT32);
        writeUuid(w, h.routerId());
        writeUuid(w, h.peerId());
    }

    private static MessageHeader readHeader(ByteReader r) {
        long timestampNanos = r.readUint64();
        long receivedAtNanos = r.readUint64();
        int collectorId = (int) r.readUint32();
        UUID routerId = readUuid(r);
        UUID peerId = readUuid(r);
        return new MessageHeader(timestampNanos, receivedAtNanos, collectorId, routerId, peerId);
    }

    private static void writeUuid(ByteWriter w, UUID u) {
        w.writeUint64(u.getMostSignificantBits());
        w.writeUint64(u.getLeastSignificantBits());
    }

    private static UUID readUuid(ByteReader r) {
        long msb = r.readUint64();
        long lsb = r.readUint64();
        return new UUID(msb, lsb);
    }

    private static void writeOptLong(ByteWriter w, OptionalLong opt) {
        if (opt.isPresent()) {
            w.writeUint8(1);
            w.writeUint64(opt.getAsLong());
        } else {
            w.writeUint8(0);
        }
    }

    private static OptionalLong readOptLong(ByteReader r) {
        return r.readUint8() == 1 ? OptionalLong.of(r.readUint64()) : OptionalLong.empty();
    }

    private static void writeLongArray(ByteWriter w, long[] values) {
        w.writeUint16(values.length);
        for (long v : values) {
            w.writeUint64(v);
        }
    }

    private static long[] readLongArray(ByteReader r) {
        int count = r.readUint16();
        if (count == 0) {
            return EMPTY_LONGS;
        }
        long[] out = new long[count];
        for (int i = 0; i < count; i++) {
            out[i] = r.readUint64();
        }
        return out;
    }

    /**
     * Validates that an autonomous-system number fits the four-octet ASN space (RFC 6793).
     *
     * @param asn the candidate ASN value carried in a {@code long}
     * @return the same value, unchanged
     * @throws IllegalArgumentException if {@code asn} is negative or exceeds {@code 0xFFFFFFFF}
     */
    private static long requireUint32Asn(long asn) {
        if (asn < 0 || asn > MAX_UINT32) {
            throw new IllegalArgumentException("ASN out of 32-bit range (RFC 6793): " + asn);
        }
        return asn;
    }

    /**
     * Writes an optional ASN as a 1-byte present flag followed, when present, by a
     * {@code uint32} (BGP AS numbers are 32-bit per RFC 6793).
     *
     * @param w   the writer
     * @param opt the optional ASN
     * @throws IllegalArgumentException if a present value is outside the 32-bit range
     */
    private static void writeOptAsn(ByteWriter w, OptionalLong opt) {
        if (opt.isPresent()) {
            w.writeUint8(1);
            w.writeUint32(requireUint32Asn(opt.getAsLong()));
        } else {
            w.writeUint8(0);
        }
    }

    /**
     * Reads an optional ASN written by {@link #writeOptAsn}: a 1-byte present flag and, when
     * set, a {@code uint32} widened into a {@code long}.
     *
     * @param r the reader
     * @return the decoded optional ASN
     */
    private static OptionalLong readOptAsn(ByteReader r) {
        return r.readUint8() == 1 ? OptionalLong.of(r.readUint32()) : OptionalLong.empty();
    }

    /**
     * Writes a {@code uint16} count followed by that many ASNs, each as a {@code uint32}
     * (RFC 6793), validating that every value fits the 32-bit range.
     *
     * @param w      the writer
     * @param values the ASN values carried in a {@code long[]}
     * @throws IllegalArgumentException if any value is outside the 32-bit range
     */
    private static void writeAsnArray(ByteWriter w, long[] values) {
        w.writeUint16(values.length);
        for (long v : values) {
            w.writeUint32(requireUint32Asn(v));
        }
    }

    /**
     * Reads a {@code uint16} count followed by that many {@code uint32} ASNs, each widened
     * into a {@code long} (the inverse of {@link #writeAsnArray}).
     *
     * @param r the reader
     * @return the decoded ASN array, or a shared empty array when the count is zero
     */
    private static long[] readAsnArray(ByteReader r) {
        int count = r.readUint16();
        if (count == 0) {
            return EMPTY_LONGS;
        }
        long[] out = new long[count];
        for (int i = 0; i < count; i++) {
            out[i] = r.readUint32();
        }
        return out;
    }

    private static byte[] readBytesU16(ByteReader r) {
        int len = r.readUint16();
        return len == 0 ? EMPTY_BYTES : r.readBytes(len);
    }

    private static byte[] readBytesU32(ByteReader r) {
        long len = r.readUint32();
        return len == 0 ? EMPTY_BYTES : r.readBytes((int) len);
    }

    private static void writeStringU16(ByteWriter w, String s) {
        byte[] utf8 = s.isEmpty() ? EMPTY_BYTES : s.getBytes(StandardCharsets.UTF_8);
        w.writeBytesU16(utf8);
    }

    private static String readStringU16(ByteReader r) {
        int len = r.readUint16();
        return len == 0 ? "" : new String(r.readBytes(len), StandardCharsets.UTF_8);
    }

    /**
     * Reads a {@code uint16}-prefixed UTF-8 string, tolerating a buffer that ends before
     * the field: if fewer than 2 bytes remain, the field is treated as absent (empty
     * string).
     */
    private static String readStringU16Tolerant(ByteReader r) {
        if (!r.isReadable(2)) {
            return "";
        }
        int len = r.readUint16();
        return len == 0 ? "" : new String(r.readBytes(len), StandardCharsets.UTF_8);
    }
}
