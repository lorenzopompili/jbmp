package it.lpworks.jbmp.protocol.parser.bmp;

import it.lpworks.jbmp.protocol.BmpParseException;
import it.lpworks.jbmp.protocol.bgp.BgpUpdate;
import it.lpworks.jbmp.protocol.bmp.BmpCommonHeader;
import it.lpworks.jbmp.protocol.bmp.BmpMessage;
import it.lpworks.jbmp.protocol.bmp.BmpMessageType;
import it.lpworks.jbmp.protocol.bmp.InitiationMessage;
import it.lpworks.jbmp.protocol.bmp.PeerDownNotification;
import it.lpworks.jbmp.protocol.bmp.PeerDownReason;
import it.lpworks.jbmp.protocol.bmp.PeerFlags;
import it.lpworks.jbmp.protocol.bmp.PeerType;
import it.lpworks.jbmp.protocol.bmp.PeerUpNotification;
import it.lpworks.jbmp.protocol.bmp.PerPeerHeader;
import it.lpworks.jbmp.protocol.bmp.RouteMirroring;
import it.lpworks.jbmp.protocol.bmp.RouteMonitoring;
import it.lpworks.jbmp.protocol.bmp.StatisticsReport;
import it.lpworks.jbmp.protocol.bmp.TerminationMessage;
import it.lpworks.jbmp.protocol.bmp.stat.AdjRibInRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.DuplicatePrefixAdvertisements;
import it.lpworks.jbmp.protocol.bmp.stat.DuplicateUpdates;
import it.lpworks.jbmp.protocol.bmp.stat.DuplicateWithdraws;
import it.lpworks.jbmp.protocol.bmp.stat.InvalidAsConfedLoop;
import it.lpworks.jbmp.protocol.bmp.stat.InvalidAsPathLoop;
import it.lpworks.jbmp.protocol.bmp.stat.InvalidClusterListLoop;
import it.lpworks.jbmp.protocol.bmp.stat.InvalidOriginatorId;
import it.lpworks.jbmp.protocol.bmp.stat.LocRibRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.PrefixesAsWithdraw;
import it.lpworks.jbmp.protocol.bmp.stat.PrefixesRejected;
import it.lpworks.jbmp.protocol.bmp.stat.StatCounter;
import it.lpworks.jbmp.protocol.bmp.stat.UnknownStat;
import it.lpworks.jbmp.protocol.bmp.stat.UpdatesAsWithdraw;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationType;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationType;
import it.lpworks.jbmp.protocol.io.ByteReader;
import it.lpworks.jbmp.protocol.parser.ParseMode;
import it.lpworks.jbmp.protocol.parser.bgp.BgpUpdateParser;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * Parser for the BMP (BGP Monitoring Protocol) message layer.
 *
 * <p>Decodes a single, fully-framed BMP message — that is, the fixed common header
 * (RFC 7854 §4.1) followed by the type-specific body — into a {@link BmpMessage}.
 * TCP stream framing (splitting the byte stream into individual messages on the
 * 4-byte length field) is the caller's responsibility; every {@code parse} entry
 * point assumes its input is exactly one complete message.
 *
 * <p>The body of a Route Monitoring message (RFC 7854 §4.6) is a complete BGP
 * UPDATE; its decoding is delegated to
 * {@link BgpUpdateParser#parse(ByteReader, ParseMode, boolean)}.
 *
 * <p>Framing errors (a truncated common header, an out-of-range message length, an
 * unknown message type, or a body that does not match its declared length) are
 * always fatal and raise {@link BmpParseException} irrespective of the
 * {@link ParseMode}; the mode governs only the recoverable, content-level cases
 * forwarded to the BGP layer.
 *
 * <p>This class is a stateless collection of static methods and cannot be
 * instantiated.
 */
public final class BmpParser {

    /** Length in bytes of the BMP common header (RFC 7854 §4.1). */
    private static final int COMMON_HEADER_LEN = 6;

    /** Length in bytes of the per-peer header (RFC 7854 §4.2). */
    private static final int PER_PEER_HEADER_LEN = 42;

    /** Length in bytes of the peer/local address field in the per-peer header. */
    private static final int ADDRESS_FIELD_LEN = 16;

    /** Length in bytes of an IPv4 address (the trailing 4 bytes of the 16-byte field). */
    private static final int IPV4_LEN = 4;

    /** Length in bytes of the marker that prefixes every BGP message (RFC 4271 §4.1). */
    private static final int BGP_MARKER_LEN = 16;

    /** Length in bytes of the fixed BGP message header: marker + length + type. */
    private static final int BGP_HEADER_LEN = 19;

    /** Smallest legal BGP message length (header only). */
    private static final int BGP_MIN_LEN = 19;

    /** Largest legal BGP message length (RFC 4271 §4.1). */
    private static final int BGP_MAX_LEN = 4096;

    /** The mandatory BMP protocol version (RFC 7854 §4.1). */
    private static final int BMP_VERSION = 3;

    /** Route Mirroring TLV type 0: a mirrored BGP message (RFC 7854 §4.7). */
    private static final int MIRROR_TLV_BGP_MESSAGE = 0;

    /** Route Mirroring TLV type 1: a mirroring information code (RFC 7854 §4.7). */
    private static final int MIRROR_TLV_INFORMATION = 1;

    private BmpParser() {
    }

    /**
     * Parses one complete BMP message from a byte array.
     *
     * @param message the raw bytes of exactly one BMP message, common header included
     * @param mode    the parse mode forwarded to the BGP layer
     * @return the decoded message body
     * @throws BmpParseException    if the message is malformed at the framing level,
     *                              or (in {@link ParseMode#STRICT}) at the content level
     * @throws NullPointerException if {@code message} or {@code mode} is {@code null}
     */
    public static BmpMessage parse(byte[] message, ParseMode mode) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(mode, "mode");
        return parse(new ByteReader(message), mode);
    }

    /**
     * Parses one complete BMP message from a reader.
     *
     * <p>The reader must be positioned at the start of the common header and is
     * expected to contain the whole message. The declared message length is honoured:
     * exactly {@code messageLength - 6} body bytes are sliced out and parsed.
     *
     * @param reader the reader positioned at the common header
     * @param mode   the parse mode forwarded to the BGP layer
     * @return the decoded message body
     * @throws BmpParseException    if the message is malformed at the framing level,
     *                              or (in {@link ParseMode#STRICT}) at the content level
     * @throws NullPointerException if {@code reader} or {@code mode} is {@code null}
     */
    public static BmpMessage parse(ByteReader reader, ParseMode mode) {
        Objects.requireNonNull(reader, "reader");
        Objects.requireNonNull(mode, "mode");

        BmpCommonHeader header = parseHeader(reader);
        long payloadLength = header.messageLength() - COMMON_HEADER_LEN;
        if (payloadLength > reader.readableBytes()) {
            throw new BmpParseException(
                    "Declared message length " + header.messageLength()
                            + " exceeds available bytes (" + (reader.readableBytes() + COMMON_HEADER_LEN)
                            + ")",
                    reader.position());
        }
        ByteReader body = reader.slice((int) payloadLength);

        return switch (header.type()) {
            case INITIATION -> parseInitiation(body);
            case TERMINATION -> parseTermination(body);
            case ROUTE_MONITORING -> parseRouteMonitoring(body, mode);
            case STATISTICS_REPORT -> parseStatisticsReport(body);
            case PEER_DOWN -> parsePeerDown(body);
            case PEER_UP -> parsePeerUp(body);
            case ROUTE_MIRRORING -> parseRouteMirroring(body);
        };
    }

    /**
     * Parses the 6-byte BMP common header (RFC 7854 §4.1).
     *
     * <p>The header is {@code version(1) | messageLength(4) | type(1)}, where
     * {@code messageLength} is an unsigned 32-bit value that <em>includes</em> the
     * header itself and so must be at least {@value #COMMON_HEADER_LEN}.
     *
     * @param reader the reader positioned at the start of the header
     * @return the decoded common header
     * @throws BmpParseException    if the header is truncated, carries a version other
     *                              than {@value #BMP_VERSION}, declares a length below
     *                              the minimum, or carries an unknown message type
     * @throws NullPointerException if {@code reader} is {@code null}
     */
    public static BmpCommonHeader parseHeader(ByteReader reader) {
        Objects.requireNonNull(reader, "reader");
        int startOffset = reader.position();
        reader.require(COMMON_HEADER_LEN);

        int version = reader.readUint8();
        if (version != BMP_VERSION) {
            throw new BmpParseException(
                    "Unsupported BMP version " + version + " (expected " + BMP_VERSION + ")",
                    startOffset);
        }

        long messageLength = reader.readUint32();
        if (messageLength < COMMON_HEADER_LEN) {
            throw new BmpParseException(
                    "BMP message length " + messageLength + " is below the 6-byte header minimum",
                    startOffset);
        }

        int typeCode = reader.readUint8();
        BmpMessageType type = BmpMessageType.fromCode(typeCode)
                .orElseThrow(() -> new BmpParseException(
                        "Unknown BMP message type " + typeCode, startOffset));

        return new BmpCommonHeader(version, messageLength, type);
    }

    // ------------------------------------------------------------------
    // Per-peer header (RFC 7854 §4.2)
    // ------------------------------------------------------------------

    /**
     * Parses the 42-byte per-peer header (RFC 7854 §4.2).
     *
     * <p>Field layout: {@code peerType(1) | peerFlags(1) | distinguisher(8) |
     * peerAddress(16) | peerAsn(4) | bgpId(4) | timestampSec(4) | timestampMicros(4)}.
     *
     * <p>The peer address field is always 16 bytes; when the V (IPv6) flag is clear
     * the IPv4 address occupies the <em>last</em> four bytes of that field. When both
     * timestamp components are zero — some implementations omit the timestamp — the
     * current instant is substituted.
     *
     * @param reader the reader positioned at the start of the per-peer header
     * @return the decoded per-peer header
     * @throws BmpParseException if the header is truncated, the peer type is unknown,
     *                           or the address bytes cannot form an {@link InetAddress}
     */
    private static PerPeerHeader parsePeerHeader(ByteReader reader) {
        int startOffset = reader.position();
        reader.require(PER_PEER_HEADER_LEN);

        int peerTypeCode = reader.readUint8();
        PeerType peerType = PeerType.fromCode(peerTypeCode)
                .orElseThrow(() -> new BmpParseException(
                        "Unknown BMP peer type " + peerTypeCode, startOffset));

        int flagsByte = reader.readUint8();
        PeerFlags flags = PeerFlags.fromByte(flagsByte);

        byte[] distinguisher = reader.readBytes(8);

        byte[] addressField = reader.readBytes(ADDRESS_FIELD_LEN);
        InetAddress address = toAddress(addressField, flags.ipv6(), reader.position());

        long peerAsn = reader.readUint32();

        byte[] bgpIdBytes = reader.readBytes(IPV4_LEN);
        Inet4Address bgpId = toInet4Address(bgpIdBytes, reader.position());

        long timestampSec = reader.readUint32();
        long timestampMicros = reader.readUint32();
        Instant timestamp = (timestampSec == 0L && timestampMicros == 0L)
                ? Instant.now()
                : Instant.ofEpochSecond(timestampSec, timestampMicros * 1_000L);

        return new PerPeerHeader(
                peerType, flags, distinguisher, address, peerAsn, bgpId, timestamp);
    }

    /**
     * Builds an {@link InetAddress} from a 16-byte address field, honouring the IPv4
     * quirk of the per-peer/peer-up headers (the IPv4 address is the trailing 4 bytes).
     *
     * @param field    the 16-byte address field
     * @param ipv6     whether the V flag marks the address as IPv6
     * @param offset   the absolute offset to report on failure
     * @return the decoded address
     * @throws BmpParseException if the bytes cannot form an address
     */
    private static InetAddress toAddress(byte[] field, boolean ipv6, int offset) {
        try {
            if (ipv6) {
                return InetAddress.getByAddress(field);
            }
            byte[] v4 = new byte[IPV4_LEN];
            System.arraycopy(field, ADDRESS_FIELD_LEN - IPV4_LEN, v4, 0, IPV4_LEN);
            return InetAddress.getByAddress(v4);
        } catch (UnknownHostException e) {
            throw new BmpParseException("Invalid peer address bytes", offset);
        }
    }

    /**
     * Builds an {@link Inet4Address} from exactly four bytes (used for the BGP ID).
     *
     * @param bytes  the 4 address bytes
     * @param offset the absolute offset to report on failure
     * @return the decoded IPv4 address
     * @throws BmpParseException if the bytes cannot form an IPv4 address
     */
    private static Inet4Address toInet4Address(byte[] bytes, int offset) {
        try {
            return (Inet4Address) InetAddress.getByAddress(bytes);
        } catch (UnknownHostException | ClassCastException e) {
            throw new BmpParseException("Invalid IPv4 address bytes", offset);
        }
    }

    // ------------------------------------------------------------------
    // Type 4: Initiation (RFC 7854 §4.3)
    // ------------------------------------------------------------------

    /**
     * Parses an Initiation message body: a sequence of Information TLVs.
     *
     * @param body the message body (no per-peer header)
     * @return the decoded Initiation message
     * @throws BmpParseException if a TLV is truncated
     */
    private static InitiationMessage parseInitiation(ByteReader body) {
        List<InformationTlv> tlvs = new ArrayList<>();
        while (body.readableBytes() > 0) {
            int type = readTlvType(body);
            byte[] value = readTlvValue(body);
            tlvs.add(new InformationTlv(InformationType.fromCode(type), type, value));
        }
        return new InitiationMessage(tlvs);
    }

    // ------------------------------------------------------------------
    // Type 5: Termination (RFC 7854 §4.4)
    // ------------------------------------------------------------------

    /**
     * Parses a Termination message body: a sequence of Termination TLVs.
     *
     * @param body the message body (no per-peer header)
     * @return the decoded Termination message
     * @throws BmpParseException if a TLV is truncated
     */
    private static TerminationMessage parseTermination(ByteReader body) {
        List<TerminationTlv> tlvs = new ArrayList<>();
        while (body.readableBytes() > 0) {
            int type = readTlvType(body);
            byte[] value = readTlvValue(body);
            tlvs.add(new TerminationTlv(TerminationType.fromCode(type), type, value));
        }
        return new TerminationMessage(tlvs);
    }

    // ------------------------------------------------------------------
    // Type 0: Route Monitoring (RFC 7854 §4.6)
    // ------------------------------------------------------------------

    /**
     * Parses a Route Monitoring message: a per-peer header followed by a complete BGP
     * UPDATE. The remaining body is forwarded to the BGP layer, with the AS_PATH
     * encoding width taken from the peer flags' A bit.
     *
     * @param body the message body
     * @param mode the parse mode forwarded to the BGP layer
     * @return the decoded Route Monitoring message
     * @throws BmpParseException if the per-peer header or the BGP UPDATE is malformed
     */
    private static RouteMonitoring parseRouteMonitoring(ByteReader body, ParseMode mode) {
        PerPeerHeader peerHeader = parsePeerHeader(body);
        ByteReader bgpMessage = body.slice(body.readableBytes());
        BgpUpdate update = BgpUpdateParser.parse(bgpMessage, mode, peerHeader.flags().twoByteAsPath());
        return new RouteMonitoring(peerHeader, update);
    }

    // ------------------------------------------------------------------
    // Type 1: Statistics Report (RFC 7854 §4.8)
    // ------------------------------------------------------------------

    /**
     * Parses a Statistics Report message: a per-peer header, a 4-byte counter count,
     * and that many {@code (type, length, value)} statistic entries.
     *
     * <p>A 4-byte value is decoded as an unsigned 32-bit counter, an 8-byte value as a
     * 64-bit gauge; any other type code or unexpected length yields an
     * {@link UnknownStat} preserving the raw value bytes.
     *
     * @param body the message body
     * @return the decoded Statistics Report message
     * @throws BmpParseException if the body or any counter entry is truncated
     */
    private static StatisticsReport parseStatisticsReport(ByteReader body) {
        PerPeerHeader peerHeader = parsePeerHeader(body);
        long count = body.readUint32();
        List<StatCounter> counters = new ArrayList<>();
        for (long i = 0; i < count; i++) {
            int statType = body.readUint16();
            int length = body.readUint16();
            int valueOffset = body.position();
            byte[] value = body.readBytes(length);
            counters.add(decodeStat(statType, length, value, valueOffset));
        }
        return new StatisticsReport(peerHeader, counters);
    }

    /**
     * Maps a {@code (type, length, value)} statistic to its modelled record, falling
     * back to {@link UnknownStat} for unknown types or unexpected value widths.
     *
     * @param statType the on-wire statistic type code
     * @param length   the declared value length
     * @param value    the raw value bytes (already read)
     * @param offset   the absolute offset of the value (for diagnostics)
     * @return the decoded statistic counter
     * @throws BmpParseException if a numeric value cannot be decoded for its length
     */
    private static StatCounter decodeStat(int statType, int length, byte[] value, int offset) {
        ByteReader valueReader = new ByteReader(value);
        if (length == 4) {
            long v = valueReader.readUint32();
            return switch (statType) {
                case 0 -> new PrefixesRejected(v);
                case 1 -> new DuplicatePrefixAdvertisements(v);
                case 2 -> new DuplicateWithdraws(v);
                case 3 -> new InvalidClusterListLoop(v);
                case 4 -> new InvalidAsPathLoop(v);
                case 5 -> new InvalidOriginatorId(v);
                case 6 -> new InvalidAsConfedLoop(v);
                case 11 -> new UpdatesAsWithdraw(v);
                case 12 -> new PrefixesAsWithdraw(v);
                case 13 -> new DuplicateUpdates(v);
                default -> new UnknownStat(statType, value);
            };
        }
        if (length == 8) {
            long v = valueReader.readUint64();
            return switch (statType) {
                case 7 -> new AdjRibInRoutes(v);
                case 8 -> new LocRibRoutes(v);
                default -> new UnknownStat(statType, value);
            };
        }
        return new UnknownStat(statType, value);
    }

    // ------------------------------------------------------------------
    // Type 2: Peer Down (RFC 7854 §4.9)
    // ------------------------------------------------------------------

    /**
     * Parses a Peer Down Notification: a per-peer header, a 1-byte reason code and a
     * reason-specific payload.
     *
     * <p>Reasons 1 and 3 carry a BGP NOTIFICATION in the remaining bytes; reason 2
     * carries a 2-byte FSM event code; reasons 4-6 carry whatever remains (often
     * nothing). All remaining bytes after the reason byte are stored verbatim.
     *
     * @param body the message body
     * @return the decoded Peer Down Notification
     * @throws BmpParseException if the header or reason field is truncated, or reason 2
     *                           does not carry its 2 FSM bytes
     */
    private static PeerDownNotification parsePeerDown(ByteReader body) {
        PerPeerHeader peerHeader = parsePeerHeader(body);
        int reasonCode = body.readUint8();
        byte[] data;
        if (reasonCode == 2) {
            // FSM event code is exactly 2 bytes.
            data = body.readBytes(2);
        } else {
            data = body.readBytes(body.readableBytes());
        }
        return new PeerDownNotification(
                peerHeader, reasonCode, PeerDownReason.fromCode(reasonCode), data);
    }

    // ------------------------------------------------------------------
    // Type 3: Peer Up (RFC 7854 §4.10)
    // ------------------------------------------------------------------

    /**
     * Parses a Peer Up Notification: a per-peer header, the local address/port pair,
     * the remote port, the sent and received BGP OPEN messages (kept raw), and any
     * trailing Information TLVs.
     *
     * <p>The local address field shares the IPv4-last-4-bytes quirk keyed off the
     * per-peer V flag. Each OPEN message is framed by its own BGP header: the 2-byte
     * length at offset 16 gives the total OPEN length, which is validated to lie in
     * {@code [19, 4096]} before exactly that many bytes are consumed as the raw OPEN.
     *
     * @param body the message body
     * @return the decoded Peer Up Notification
     * @throws BmpParseException if any field or either OPEN message is truncated or the
     *                           OPEN length is out of range
     */
    private static PeerUpNotification parsePeerUp(ByteReader body) {
        PerPeerHeader peerHeader = parsePeerHeader(body);

        byte[] localField = body.readBytes(ADDRESS_FIELD_LEN);
        InetAddress localAddress = toAddress(localField, peerHeader.flags().ipv6(), body.position());
        int localPort = body.readUint16();
        int remotePort = body.readUint16();

        byte[] sentOpen = readOpenMessage(body);
        byte[] recvOpen = readOpenMessage(body);

        List<InformationTlv> tlvs = new ArrayList<>();
        while (body.readableBytes() > 0) {
            int type = readTlvType(body);
            byte[] value = readTlvValue(body);
            tlvs.add(new InformationTlv(InformationType.fromCode(type), type, value));
        }

        return new PeerUpNotification(
                peerHeader, localAddress, localPort, remotePort, sentOpen, recvOpen, tlvs);
    }

    /**
     * Reads one raw, self-framed BGP message (an OPEN) from the reader.
     *
     * <p>The 2-byte length lives at offset {@value #BGP_MARKER_LEN} of the BGP header;
     * it is peeked without consuming the header so the full message — header included —
     * can be returned verbatim.
     *
     * @param reader the reader positioned at the start of the BGP message
     * @return the raw bytes of the whole BGP message
     * @throws BmpParseException if the message is truncated or its declared length is
     *                           outside {@code [19, 4096]}
     */
    private static byte[] readOpenMessage(ByteReader reader) {
        int start = reader.position();
        reader.require(BGP_HEADER_LEN);
        // Peek the 2-byte length at offset 16 without consuming the header.
        reader.skip(BGP_MARKER_LEN);
        int openLength = reader.readUint16();
        reader.position(start);
        if (openLength < BGP_MIN_LEN || openLength > BGP_MAX_LEN) {
            throw new BmpParseException(
                    "BGP OPEN length " + openLength + " outside [" + BGP_MIN_LEN + ", "
                            + BGP_MAX_LEN + "]",
                    start);
        }
        return reader.readBytes(openLength);
    }

    // ------------------------------------------------------------------
    // Type 6: Route Mirroring (RFC 7854 §4.7)
    // ------------------------------------------------------------------

    /**
     * Parses a Route Mirroring message: a per-peer header followed by TLVs. A type-0
     * TLV carries a mirrored BGP message (kept raw); a type-1 TLV carries a 2-byte
     * information code. If multiple BGP-message TLVs are present the last one wins; the
     * information code is reported only when a type-1 TLV is present.
     *
     * @param body the message body
     * @return the decoded Route Mirroring message
     * @throws BmpParseException if the header or any TLV is truncated
     */
    private static RouteMirroring parseRouteMirroring(ByteReader body) {
        PerPeerHeader peerHeader = parsePeerHeader(body);
        byte[] mirroredBgpMessage = new byte[0];
        OptionalInt informationCode = OptionalInt.empty();
        while (body.readableBytes() > 0) {
            int type = readTlvType(body);
            byte[] value = readTlvValue(body);
            if (type == MIRROR_TLV_BGP_MESSAGE) {
                mirroredBgpMessage = value;
            } else if (type == MIRROR_TLV_INFORMATION) {
                if (value.length >= 2) {
                    informationCode = OptionalInt.of(((value[0] & 0xFF) << 8) | (value[1] & 0xFF));
                } else {
                    informationCode = OptionalInt.of(0);
                }
            }
            // Unknown TLV types are ignored, their value already consumed.
        }
        return new RouteMirroring(peerHeader, mirroredBgpMessage, informationCode);
    }

    // ------------------------------------------------------------------
    // Shared TLV helpers (type/length/value)
    // ------------------------------------------------------------------

    /**
     * Reads a 2-byte TLV type field.
     *
     * @param reader the reader positioned at the TLV type
     * @return the unsigned 16-bit type
     * @throws BmpParseException if fewer than 2 bytes remain
     */
    private static int readTlvType(ByteReader reader) {
        return reader.readUint16();
    }

    /**
     * Reads a TLV value: a 2-byte length followed by that many value bytes.
     *
     * @param reader the reader positioned at the TLV length
     * @return the value bytes (a fresh copy)
     * @throws BmpParseException if the length is truncated or exceeds the remaining bytes
     */
    private static byte[] readTlvValue(ByteReader reader) {
        int length = reader.readUint16();
        return reader.readBytes(length);
    }
}
