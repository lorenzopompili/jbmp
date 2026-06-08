package it.lpworks.jbmp.protocol.builder;

import it.lpworks.jbmp.protocol.bmp.BmpMessageType;
import it.lpworks.jbmp.protocol.bmp.PeerFlags;
import it.lpworks.jbmp.protocol.bmp.PerPeerHeader;
import it.lpworks.jbmp.protocol.bmp.stat.AdjRibInRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.LocRibRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.StatCounter;
import it.lpworks.jbmp.protocol.bmp.stat.UnknownStat;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationTlv;
import it.lpworks.jbmp.protocol.io.ByteWriter;

import java.net.InetAddress;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * Encodes complete, fully-framed BMP messages (RFC 7854), the inverse of
 * {@link it.lpworks.jbmp.protocol.parser.bmp.BmpParser}.
 *
 * <p>Every builder produces a complete message: the 6-octet common header
 * (RFC 7854 §4.1) — version {@code 3}, a back-patched 4-octet total length and the
 * message-type octet — followed by the type-specific body. The per-peer header
 * (RFC 7854 §4.2) is encoded by {@link #writePerPeerHeader(ByteWriter, PerPeerHeader)}
 * including the IPv4 quirk: when the peer's V flag is clear the four IPv4 octets
 * occupy the last four octets of the 16-octet address field.
 *
 * <p>Statistic values are emitted at the width the parser expects for each type
 * (RFC 7854 §4.8): the 32-bit counters as four octets and the 64-bit gauges
 * (AdjRibInRoutes, LocRibRoutes) as eight, so they round-trip back to the same
 * concrete {@link StatCounter} records. An {@link UnknownStat} is emitted verbatim
 * with its preserved type code and raw value bytes.
 *
 * <p>This class is a stateless collection of static methods and cannot be
 * instantiated.
 */
public final class BmpMessageBuilder {

    /** The mandatory BMP protocol version (RFC 7854 §4.1). */
    private static final int BMP_VERSION = 3;

    /** Length, in octets, of the BMP common header (RFC 7854 §4.1). */
    private static final int COMMON_HEADER_LEN = 6;

    /** Length, in octets, of the per-peer address field (RFC 7854 §4.2). */
    private static final int ADDRESS_FIELD_LEN = 16;

    /** Length, in octets, of an IPv4 address. */
    private static final int IPV4_LEN = 4;

    /** V (IPv6) flag bit of the per-peer flags octet (RFC 7854 §4.2). */
    private static final int FLAG_V = 0x80;

    /** L (post-policy) flag bit of the per-peer flags octet (RFC 7854 §4.2). */
    private static final int FLAG_L = 0x40;

    /** A (2-byte AS_PATH) flag bit of the per-peer flags octet (RFC 7854 §4.2). */
    private static final int FLAG_A = 0x20;

    /** Number of nanoseconds in one microsecond. */
    private static final int NANOS_PER_MICRO = 1_000;

    /** Route Mirroring TLV type 0: a mirrored BGP message (RFC 7854 §4.7). */
    private static final int MIRROR_TLV_BGP_MESSAGE = 0;

    /** Route Mirroring TLV type 1: a mirroring information code (RFC 7854 §4.7). */
    private static final int MIRROR_TLV_INFORMATION = 1;

    private BmpMessageBuilder() {
        // Utility holder; not instantiable.
    }

    // ------------------------------------------------------------------
    // Type 4: Initiation (RFC 7854 §4.3)
    // ------------------------------------------------------------------

    /**
     * Builds an Initiation message: a sequence of Information TLVs.
     *
     * @param tlvs the Information TLVs (may be empty)
     * @return the encoded message, common header included
     * @throws NullPointerException if {@code tlvs} is {@code null}
     */
    public static byte[] initiation(List<InformationTlv> tlvs) {
        Objects.requireNonNull(tlvs, "tlvs");
        ByteWriter writer = new ByteWriter();
        int lengthIndex = beginMessage(writer, BmpMessageType.INITIATION);
        for (InformationTlv tlv : tlvs) {
            writeTlv(writer, tlv.rawType(), tlv.value());
        }
        return finishMessage(writer, lengthIndex);
    }

    // ------------------------------------------------------------------
    // Type 5: Termination (RFC 7854 §4.4)
    // ------------------------------------------------------------------

    /**
     * Builds a Termination message: a sequence of Termination TLVs.
     *
     * @param tlvs the Termination TLVs (may be empty)
     * @return the encoded message, common header included
     * @throws NullPointerException if {@code tlvs} is {@code null}
     */
    public static byte[] termination(List<TerminationTlv> tlvs) {
        Objects.requireNonNull(tlvs, "tlvs");
        ByteWriter writer = new ByteWriter();
        int lengthIndex = beginMessage(writer, BmpMessageType.TERMINATION);
        for (TerminationTlv tlv : tlvs) {
            writeTlv(writer, tlv.rawType(), tlv.value());
        }
        return finishMessage(writer, lengthIndex);
    }

    // ------------------------------------------------------------------
    // Type 0: Route Monitoring (RFC 7854 §4.6)
    // ------------------------------------------------------------------

    /**
     * Builds a Route Monitoring message: a per-peer header followed by a complete BGP
     * message (typically built with {@link BgpUpdateBuilder#update}).
     *
     * @param peer       the per-peer header
     * @param bgpMessage the complete, framed BGP message bytes
     * @return the encoded message, common header included
     * @throws NullPointerException if any argument is {@code null}
     */
    public static byte[] routeMonitoring(PerPeerHeader peer, byte[] bgpMessage) {
        Objects.requireNonNull(peer, "peer");
        Objects.requireNonNull(bgpMessage, "bgpMessage");
        ByteWriter writer = new ByteWriter();
        int lengthIndex = beginMessage(writer, BmpMessageType.ROUTE_MONITORING);
        writePerPeerHeader(writer, peer);
        writer.writeBytes(bgpMessage);
        return finishMessage(writer, lengthIndex);
    }

    // ------------------------------------------------------------------
    // Type 1: Statistics Report (RFC 7854 §4.8)
    // ------------------------------------------------------------------

    /**
     * Builds a Statistics Report message: a per-peer header, a 4-octet counter count,
     * then each {@code (type, length, value)} statistic entry.
     *
     * @param peer     the per-peer header
     * @param counters the statistic counters (may be empty)
     * @return the encoded message, common header included
     * @throws NullPointerException if any argument is {@code null}
     */
    public static byte[] statisticsReport(PerPeerHeader peer, List<StatCounter> counters) {
        Objects.requireNonNull(peer, "peer");
        Objects.requireNonNull(counters, "counters");
        ByteWriter writer = new ByteWriter();
        int lengthIndex = beginMessage(writer, BmpMessageType.STATISTICS_REPORT);
        writePerPeerHeader(writer, peer);
        writer.writeUint32(counters.size());
        for (StatCounter counter : counters) {
            writeStat(writer, counter);
        }
        return finishMessage(writer, lengthIndex);
    }

    /**
     * Encodes a single statistic entry: a 2-octet type, a 2-octet length and the value.
     *
     * <p>The value width is chosen to match the parser's length-based dispatch: the
     * 64-bit gauges (AdjRibInRoutes, LocRibRoutes) emit eight octets and all other
     * modelled counters emit four; an {@link UnknownStat} emits its raw bytes verbatim.
     *
     * @param writer  the destination writer
     * @param counter the statistic to encode
     */
    private static void writeStat(ByteWriter writer, StatCounter counter) {
        writer.writeUint16(counter.statType());
        switch (counter) {
            case AdjRibInRoutes ignored -> {
                writer.writeUint16(8);
                writer.writeUint64(counter.value());
            }
            case LocRibRoutes ignored -> {
                writer.writeUint16(8);
                writer.writeUint64(counter.value());
            }
            case UnknownStat unknown -> {
                byte[] raw = unknown.rawBytes();
                writer.writeUint16(raw.length);
                writer.writeBytes(raw);
            }
            default -> {
                // All remaining modelled counters are 32-bit (RFC 7854 §4.8).
                writer.writeUint16(4);
                writer.writeUint32(counter.value() & 0xFFFFFFFFL);
            }
        }
    }

    // ------------------------------------------------------------------
    // Type 3: Peer Up (RFC 7854 §4.10)
    // ------------------------------------------------------------------

    /**
     * Builds a Peer Up Notification: a per-peer header, the local address/port pair,
     * the remote port, the sent and received BGP OPEN messages (raw, self-framed), and
     * any trailing Information TLVs.
     *
     * <p>The local address shares the IPv4-last-4-octets quirk of the per-peer header,
     * keyed off the peer's V flag.
     *
     * @param peer         the per-peer header
     * @param localAddress the local TCP-session address
     * @param localPort    the local TCP port, in {@code [0, 65535]}
     * @param remotePort   the remote TCP port, in {@code [0, 65535]}
     * @param sentOpen     the raw sent BGP OPEN message bytes
     * @param receivedOpen the raw received BGP OPEN message bytes
     * @param tlvs         the Information TLVs (may be empty)
     * @return the encoded message, common header included
     * @throws NullPointerException if any reference argument is {@code null}
     */
    public static byte[] peerUp(PerPeerHeader peer, InetAddress localAddress, int localPort,
                                int remotePort, byte[] sentOpen, byte[] receivedOpen,
                                List<InformationTlv> tlvs) {
        Objects.requireNonNull(peer, "peer");
        Objects.requireNonNull(localAddress, "localAddress");
        Objects.requireNonNull(sentOpen, "sentOpen");
        Objects.requireNonNull(receivedOpen, "receivedOpen");
        Objects.requireNonNull(tlvs, "tlvs");

        ByteWriter writer = new ByteWriter();
        int lengthIndex = beginMessage(writer, BmpMessageType.PEER_UP);
        writePerPeerHeader(writer, peer);
        writeAddressField(writer, localAddress, peer.flags().ipv6());
        writer.writeUint16(localPort);
        writer.writeUint16(remotePort);
        writer.writeBytes(sentOpen);
        writer.writeBytes(receivedOpen);
        for (InformationTlv tlv : tlvs) {
            writeTlv(writer, tlv.rawType(), tlv.value());
        }
        return finishMessage(writer, lengthIndex);
    }

    // ------------------------------------------------------------------
    // Type 2: Peer Down (RFC 7854 §4.9)
    // ------------------------------------------------------------------

    /**
     * Builds a Peer Down Notification: a per-peer header, a 1-octet reason code and a
     * reason-specific payload.
     *
     * @param peer       the per-peer header
     * @param reasonCode the reason code, in {@code [0, 255]}
     * @param data       the reason-specific payload bytes (may be empty)
     * @return the encoded message, common header included
     * @throws NullPointerException if {@code peer} or {@code data} is {@code null}
     */
    public static byte[] peerDown(PerPeerHeader peer, int reasonCode, byte[] data) {
        Objects.requireNonNull(peer, "peer");
        Objects.requireNonNull(data, "data");
        ByteWriter writer = new ByteWriter();
        int lengthIndex = beginMessage(writer, BmpMessageType.PEER_DOWN);
        writePerPeerHeader(writer, peer);
        writer.writeUint8(reasonCode);
        writer.writeBytes(data);
        return finishMessage(writer, lengthIndex);
    }

    // ------------------------------------------------------------------
    // Type 6: Route Mirroring (RFC 7854 §4.7)
    // ------------------------------------------------------------------

    /**
     * Builds a Route Mirroring message: a per-peer header followed by a type-0 TLV
     * carrying the mirrored BGP message and, when present, a type-1 TLV carrying a
     * 2-octet information code.
     *
     * @param peer               the per-peer header
     * @param mirroredBgpMessage the raw mirrored BGP message bytes (may be empty)
     * @param informationCode    the mirroring information code, if any
     * @return the encoded message, common header included
     * @throws NullPointerException if any reference argument is {@code null}
     */
    public static byte[] routeMirroring(PerPeerHeader peer, byte[] mirroredBgpMessage,
                                        OptionalInt informationCode) {
        Objects.requireNonNull(peer, "peer");
        Objects.requireNonNull(mirroredBgpMessage, "mirroredBgpMessage");
        Objects.requireNonNull(informationCode, "informationCode");

        ByteWriter writer = new ByteWriter();
        int lengthIndex = beginMessage(writer, BmpMessageType.ROUTE_MIRRORING);
        writePerPeerHeader(writer, peer);
        writeTlv(writer, MIRROR_TLV_BGP_MESSAGE, mirroredBgpMessage);
        if (informationCode.isPresent()) {
            ByteWriter code = new ByteWriter(2);
            code.writeUint16(informationCode.getAsInt());
            writeTlv(writer, MIRROR_TLV_INFORMATION, code.toByteArray());
        }
        return finishMessage(writer, lengthIndex);
    }

    // ------------------------------------------------------------------
    // Common header helpers
    // ------------------------------------------------------------------

    /**
     * Writes the common-header prefix — version and a reserved length placeholder — and
     * the message-type octet, returning the placeholder index for back-patching.
     *
     * @param writer the destination writer
     * @param type   the message type
     * @return the index of the reserved 4-octet length placeholder
     */
    private static int beginMessage(ByteWriter writer, BmpMessageType type) {
        writer.writeUint8(BMP_VERSION);
        int lengthIndex = writer.reserveUint32();
        writer.writeUint8(type.code());
        return lengthIndex;
    }

    /**
     * Back-patches the common-header total length with the final message size and
     * returns the encoded bytes.
     *
     * @param writer      the writer holding the complete message
     * @param lengthIndex the reserved length placeholder index
     * @return the encoded message bytes
     */
    private static byte[] finishMessage(ByteWriter writer, int lengthIndex) {
        writer.patchUint32(lengthIndex, writer.length());
        return writer.toByteArray();
    }

    // ------------------------------------------------------------------
    // Per-peer header (RFC 7854 §4.2)
    // ------------------------------------------------------------------

    /**
     * Writes the 42-octet per-peer header (RFC 7854 §4.2).
     *
     * <p>Field layout: {@code peerType(1) | flags(1) | distinguisher(8) | address(16) |
     * asn(4) | bgpId(4) | timestampSec(4) | timestampMicros(4)}. The address field is
     * always 16 octets; an IPv4 peer address is placed in the trailing four octets.
     * The timestamp seconds and microseconds are derived from the header's
     * {@link Instant}.
     *
     * @param writer the destination writer
     * @param peer   the per-peer header to encode
     */
    private static void writePerPeerHeader(ByteWriter writer, PerPeerHeader peer) {
        writer.writeUint8(peer.peerType().code());
        writer.writeUint8(encodeFlags(peer.flags()));
        writer.writeBytes(peer.distinguisher());
        writeAddressField(writer, peer.address(), peer.flags().ipv6());
        writer.writeUint32(peer.peerAsn());
        writer.writeBytes(peer.bgpId().getAddress());

        Instant timestamp = peer.timestamp();
        long seconds = timestamp.getEpochSecond();
        long micros = timestamp.getNano() / NANOS_PER_MICRO;
        writer.writeUint32(seconds & 0xFFFFFFFFL);
        writer.writeUint32(micros & 0xFFFFFFFFL);
    }

    /**
     * Encodes the per-peer flags octet (V/L/A bits) from a {@link PeerFlags}.
     *
     * @param flags the decoded flags
     * @return the flags octet
     */
    private static int encodeFlags(PeerFlags flags) {
        int b = 0;
        if (flags.ipv6()) {
            b |= FLAG_V;
        }
        if (flags.postPolicy()) {
            b |= FLAG_L;
        }
        if (flags.twoByteAsPath()) {
            b |= FLAG_A;
        }
        return b;
    }

    /**
     * Writes a 16-octet address field, honouring the IPv4 quirk: an IPv4 address is
     * left-padded with zero octets so it occupies the trailing four octets of the
     * field (RFC 7854 §4.2).
     *
     * @param writer  the destination writer
     * @param address the address to encode
     * @param ipv6    whether the peer's V flag marks the address as IPv6
     */
    private static void writeAddressField(ByteWriter writer, InetAddress address, boolean ipv6) {
        byte[] raw = address.getAddress();
        byte[] field = new byte[ADDRESS_FIELD_LEN];
        if (ipv6) {
            // A full 16-octet IPv6 address fills the field directly.
            System.arraycopy(raw, 0, field, 0, raw.length);
        } else {
            // The 4 IPv4 octets occupy the last 4 octets of the field.
            System.arraycopy(raw, 0, field, ADDRESS_FIELD_LEN - IPV4_LEN, IPV4_LEN);
        }
        writer.writeBytes(field);
    }

    // ------------------------------------------------------------------
    // TLV helper (type/length/value)
    // ------------------------------------------------------------------

    /**
     * Writes a TLV: a 2-octet type, a 2-octet length and the value bytes.
     *
     * @param writer the destination writer
     * @param type   the TLV type code
     * @param value  the TLV value bytes
     */
    private static void writeTlv(ByteWriter writer, int type, byte[] value) {
        writer.writeUint16(type);
        writer.writeUint16(value.length);
        writer.writeBytes(value);
    }
}
