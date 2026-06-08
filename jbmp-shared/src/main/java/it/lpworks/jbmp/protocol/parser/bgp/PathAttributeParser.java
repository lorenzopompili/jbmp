package it.lpworks.jbmp.protocol.parser.bgp;

import it.lpworks.jbmp.protocol.BmpParseException;
import it.lpworks.jbmp.protocol.bgp.Aggregator;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AtomicAggregate;
import it.lpworks.jbmp.protocol.bgp.AttributeFlags;
import it.lpworks.jbmp.protocol.bgp.ClusterList;
import it.lpworks.jbmp.protocol.bgp.Communities;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunities;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunity;
import it.lpworks.jbmp.protocol.bgp.LargeCommunities;
import it.lpworks.jbmp.protocol.bgp.LargeCommunity;
import it.lpworks.jbmp.protocol.bgp.LocalPref;
import it.lpworks.jbmp.protocol.bgp.MpReachNlri;
import it.lpworks.jbmp.protocol.bgp.MpUnreachNlri;
import it.lpworks.jbmp.protocol.bgp.MultiExitDisc;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginType;
import it.lpworks.jbmp.protocol.bgp.OriginatorId;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.bgp.UnknownAttribute;
import it.lpworks.jbmp.protocol.io.ByteReader;
import it.lpworks.jbmp.protocol.parser.ParseMode;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses the Path Attributes field of a BGP UPDATE message and dispatches each
 * attribute to its concrete {@link PathAttribute} type.
 *
 * <p>See RFC 4271 §4.3 for the generic framing (flags, type code, length, value),
 * RFC 4760 for the multiprotocol attributes, RFC 4456 for ORIGINATOR_ID and
 * CLUSTER_LIST, RFC 1997 for COMMUNITIES, RFC 4360 for EXTENDED COMMUNITIES,
 * RFC 8092 for LARGE COMMUNITIES, and RFC 6793 for 4-octet AS support (AS4_PATH and
 * AS4_AGGREGATOR, merged into AS_PATH / AGGREGATOR).
 *
 * <p>This is a package-private helper used by {@link BgpUpdateParser}.
 */
final class PathAttributeParser {

    /** Extended-length flag bit (E) in the attribute flags octet (RFC 4271 §4.3). */
    private static final int FLAG_EXTENDED_LENGTH = 0x10;

    // Well-known and optional attribute type codes.
    private static final int TYPE_ORIGIN = 1;
    private static final int TYPE_AS_PATH = 2;
    private static final int TYPE_NEXT_HOP = 3;
    private static final int TYPE_MULTI_EXIT_DISC = 4;
    private static final int TYPE_LOCAL_PREF = 5;
    private static final int TYPE_ATOMIC_AGGREGATE = 6;
    private static final int TYPE_AGGREGATOR = 7;
    private static final int TYPE_COMMUNITIES = 8;
    private static final int TYPE_ORIGINATOR_ID = 9;
    private static final int TYPE_CLUSTER_LIST = 10;
    private static final int TYPE_MP_REACH_NLRI = 14;
    private static final int TYPE_MP_UNREACH_NLRI = 15;
    private static final int TYPE_EXTENDED_COMMUNITIES = 16;
    private static final int TYPE_AS4_PATH = 17;
    private static final int TYPE_AS4_AGGREGATOR = 18;
    private static final int TYPE_LARGE_COMMUNITIES = 32;

    // Fixed lengths and stride sizes.
    private static final int IPV4_ADDRESS_BYTES = 4;
    private static final int COMMUNITY_BYTES = 4;
    private static final int EXTENDED_COMMUNITY_BYTES = 8;
    private static final int LARGE_COMMUNITY_BYTES = 12;
    private static final int AGGREGATOR_LEN_2BYTE_AS = 6;
    private static final int AGGREGATOR_LEN_4BYTE_AS = 8;

    private PathAttributeParser() {
        // Utility holder; not instantiable.
    }

    /**
     * Parses all path attributes from a reader spanning exactly the Path Attributes
     * field, applying the configured {@link ParseMode}.
     *
     * <p>In {@link ParseMode#STRICT} any malformed or truncated attribute raises
     * {@link BmpParseException}. In {@link ParseMode#LENIENT} attribute parsing stops
     * at the first malformed attribute, returning the attributes decoded so far
     * (RFC 4271 §6.3 resilience).
     *
     * <p>When {@code asPath2Byte} is {@code true}, AS_PATH is read with two-octet AS
     * numbers and any AS4_PATH / AS4_AGGREGATOR present is merged into the AS_PATH /
     * AGGREGATOR per RFC 6793 §4.2.3 rather than being surfaced as a distinct
     * attribute. When {@code asPath2Byte} is {@code false}, AS_PATH already carries
     * four-octet AS numbers and no AS4 merge applies.
     *
     * @param reader      a reader spanning exactly the Path Attributes field
     * @param mode        the parse tolerance
     * @param asPath2Byte whether AS_PATH uses two-octet AS numbers (drives AS4 merge)
     * @return the decoded path attributes in wire order, after any AS4 merge
     * @throws BmpParseException in strict mode on malformed input
     */
    static List<PathAttribute> parse(ByteReader reader, ParseMode mode, boolean asPath2Byte) {
        boolean strict = mode == ParseMode.STRICT;
        List<PathAttribute> attributes = new ArrayList<>();

        // AS4 reconstruction state (RFC 6793): captured only when reading 2-octet AS.
        AsPath asPath = null;
        AsPath as4Path = null;
        Aggregator aggregator = null;
        Aggregator as4Aggregator = null;
        int asPathIndex = -1;
        int aggregatorIndex = -1;

        while (reader.readableBytes() > 0) {
            int attributeStart = reader.position();
            try {
                int flagsByte = reader.readUint8();
                AttributeFlags flags = AttributeFlags.fromByte(flagsByte);
                int typeCode = reader.readUint8();
                int length = ((flagsByte & FLAG_EXTENDED_LENGTH) != 0)
                        ? reader.readUint16()
                        : reader.readUint8();
                ByteReader value = reader.slice(length);

                switch (typeCode) {
                    case TYPE_AS_PATH -> {
                        asPath = AsPathParser.parse(value, !asPath2Byte);
                        asPathIndex = attributes.size();
                        attributes.add(asPath);
                    }
                    case TYPE_AS4_PATH ->
                            // AS4_PATH always carries 4-octet AS numbers (RFC 6793). It is
                            // captured for the post-loop merge when the peer is 2-octet only;
                            // for 4-octet-capable peers it is redundant and simply dropped
                            // (never surfaced as a distinct attribute, per RFC 6793 §4.2.3).
                            as4Path = AsPathParser.parse(value, true);
                    case TYPE_AGGREGATOR -> {
                        aggregator = parseAggregator(value, length, attributeStart);
                        aggregatorIndex = attributes.size();
                        attributes.add(aggregator);
                    }
                    case TYPE_AS4_AGGREGATOR -> {
                        // AS4_AGGREGATOR is a 4-octet AS plus a 4-octet IPv4 address.
                        as4Aggregator = parseAggregator(value, AGGREGATOR_LEN_4BYTE_AS, attributeStart);
                    }
                    default -> attributes.add(dispatch(typeCode, flags, value, length, attributeStart));
                }
            } catch (BmpParseException | IllegalArgumentException e) {
                if (strict) {
                    throw asParseException(e, attributeStart);
                }
                // Lenient: stop attribute parsing, keep what was decoded so far.
                break;
            }
        }

        // RFC 6793 §4.2.3: reconstruct AS_PATH / AGGREGATOR from the AS4_* attributes.
        if (asPath2Byte && as4Path != null && asPath != null && asPathIndex >= 0) {
            attributes.set(asPathIndex, AsPathParser.merge(asPath, as4Path));
        }
        if (asPath2Byte && as4Aggregator != null && aggregator != null && aggregatorIndex >= 0) {
            attributes.set(aggregatorIndex, mergeAggregator(aggregator, as4Aggregator));
        }

        return attributes;
    }

    /**
     * Dispatches a single attribute (other than AS_PATH/AS4_PATH and the AGGREGATOR
     * pair, which are handled specially for AS4 reconstruction) to its concrete type.
     *
     * @param typeCode       the unsigned 8-bit attribute type code
     * @param flags          the decoded attribute flags
     * @param value          a reader spanning exactly the attribute value
     * @param length         the declared attribute value length
     * @param attributeStart the absolute offset of the attribute, for diagnostics
     * @return the decoded attribute
     * @throws BmpParseException if the attribute value is malformed or truncated
     */
    private static PathAttribute dispatch(int typeCode, AttributeFlags flags, ByteReader value,
                                          int length, int attributeStart) {
        return switch (typeCode) {
            case TYPE_ORIGIN -> parseOrigin(value, attributeStart);
            case TYPE_NEXT_HOP -> new NextHop(readInet4(value, attributeStart));
            case TYPE_MULTI_EXIT_DISC -> new MultiExitDisc(value.readUint32());
            case TYPE_LOCAL_PREF -> new LocalPref(value.readUint32());
            case TYPE_ATOMIC_AGGREGATE -> new AtomicAggregate();
            case TYPE_COMMUNITIES -> parseCommunities(value, length, attributeStart);
            case TYPE_ORIGINATOR_ID -> new OriginatorId(readInet4(value, attributeStart));
            case TYPE_CLUSTER_LIST -> parseClusterList(value, length, attributeStart);
            case TYPE_MP_REACH_NLRI -> parseMpReach(value);
            case TYPE_MP_UNREACH_NLRI -> parseMpUnreach(value);
            case TYPE_EXTENDED_COMMUNITIES -> parseExtendedCommunities(value, length, attributeStart);
            case TYPE_LARGE_COMMUNITIES -> parseLargeCommunities(value, length, attributeStart);
            default -> new UnknownAttribute(typeCode, flags, value.readBytes(value.readableBytes()));
        };
    }

    /**
     * Parses the ORIGIN attribute (RFC 4271 §5.1.1).
     *
     * @param value          a reader over the single ORIGIN octet
     * @param attributeStart the absolute offset for diagnostics
     * @return the ORIGIN attribute
     * @throws BmpParseException if the value is truncated or the origin code is unknown
     */
    private static Origin parseOrigin(ByteReader value, int attributeStart) {
        int code = value.readUint8();
        OriginType originType = OriginType.fromCode(code)
                .orElseThrow(() -> new BmpParseException(
                        "Unknown ORIGIN code " + code, attributeStart));
        return new Origin(originType);
    }

    /**
     * Parses the COMMUNITIES attribute as a sequence of 4-octet values (RFC 1997).
     *
     * @param value          a reader over the attribute value
     * @param length         the declared value length
     * @param attributeStart the absolute offset for diagnostics
     * @return the COMMUNITIES attribute
     * @throws BmpParseException if the length is not a multiple of four
     */
    private static Communities parseCommunities(ByteReader value, int length, int attributeStart) {
        requireMultiple(length, COMMUNITY_BYTES, "COMMUNITIES", attributeStart);
        int count = length / COMMUNITY_BYTES;
        int[] values = new int[count];
        for (int i = 0; i < count; i++) {
            values[i] = (int) value.readUint32();
        }
        return new Communities(values);
    }

    /**
     * Parses the CLUSTER_LIST attribute as a sequence of 4-octet CLUSTER_IDs (RFC 4456).
     *
     * @param value          a reader over the attribute value
     * @param length         the declared value length
     * @param attributeStart the absolute offset for diagnostics
     * @return the CLUSTER_LIST attribute
     * @throws BmpParseException if the length is not a multiple of four
     */
    private static ClusterList parseClusterList(ByteReader value, int length, int attributeStart) {
        requireMultiple(length, IPV4_ADDRESS_BYTES, "CLUSTER_LIST", attributeStart);
        int count = length / IPV4_ADDRESS_BYTES;
        List<Inet4Address> ids = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            ids.add(readInet4(value, attributeStart));
        }
        return new ClusterList(ids);
    }

    /**
     * Parses the EXTENDED COMMUNITIES attribute as a sequence of 8-octet values
     * (RFC 4360).
     *
     * @param value          a reader over the attribute value
     * @param length         the declared value length
     * @param attributeStart the absolute offset for diagnostics
     * @return the EXTENDED COMMUNITIES attribute
     * @throws BmpParseException if the length is not a multiple of eight
     */
    private static ExtendedCommunities parseExtendedCommunities(ByteReader value, int length,
                                                                int attributeStart) {
        requireMultiple(length, EXTENDED_COMMUNITY_BYTES, "EXTENDED_COMMUNITIES", attributeStart);
        int count = length / EXTENDED_COMMUNITY_BYTES;
        List<ExtendedCommunity> communities = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            communities.add(new ExtendedCommunity(value.readBytes(EXTENDED_COMMUNITY_BYTES)));
        }
        return new ExtendedCommunities(communities);
    }

    /**
     * Parses the LARGE COMMUNITIES attribute as a sequence of three-uint32 values
     * (RFC 8092).
     *
     * @param value          a reader over the attribute value
     * @param length         the declared value length
     * @param attributeStart the absolute offset for diagnostics
     * @return the LARGE COMMUNITIES attribute
     * @throws BmpParseException if the length is not a multiple of twelve
     */
    private static LargeCommunities parseLargeCommunities(ByteReader value, int length,
                                                          int attributeStart) {
        requireMultiple(length, LARGE_COMMUNITY_BYTES, "LARGE_COMMUNITIES", attributeStart);
        int count = length / LARGE_COMMUNITY_BYTES;
        List<LargeCommunity> communities = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            long global = value.readUint32();
            long local1 = value.readUint32();
            long local2 = value.readUint32();
            communities.add(new LargeCommunity(global, local1, local2));
        }
        return new LargeCommunities(communities);
    }

    /**
     * Parses an AGGREGATOR or AS4_AGGREGATOR value (RFC 4271 §5.1.7, RFC 6793).
     *
     * <p>A length of six denotes a 2-octet AS plus a 4-octet IPv4 address; a length of
     * eight denotes a 4-octet AS plus a 4-octet IPv4 address. The AS number is always
     * conveyed as an unsigned 32-bit value.
     *
     * @param value          a reader over the attribute value
     * @param length         the declared value length (six or eight)
     * @param attributeStart the absolute offset for diagnostics
     * @return the AGGREGATOR attribute
     * @throws BmpParseException if the length is neither six nor eight, or the value is
     *                           truncated
     */
    private static Aggregator parseAggregator(ByteReader value, int length, int attributeStart) {
        long asn;
        if (length == AGGREGATOR_LEN_2BYTE_AS) {
            asn = value.readUint16();
        } else if (length == AGGREGATOR_LEN_4BYTE_AS) {
            asn = value.readUint32();
        } else {
            throw new BmpParseException(
                    "AGGREGATOR length must be " + AGGREGATOR_LEN_2BYTE_AS + " or "
                            + AGGREGATOR_LEN_4BYTE_AS + " but was " + length, attributeStart);
        }
        Inet4Address address = readInet4(value, attributeStart);
        return new Aggregator(asn, address);
    }

    /**
     * Merges an AS4_AGGREGATOR into an AGGREGATOR per RFC 6793 §4.2.3.
     *
     * <p>If the AGGREGATOR's AS number is the AS_TRANS placeholder (23456), the true
     * 4-octet AS number and address from the AS4_AGGREGATOR replace it; otherwise the
     * AGGREGATOR is authoritative and the AS4_AGGREGATOR is ignored.
     *
     * @param aggregator    the 2-octet-AS AGGREGATOR
     * @param as4Aggregator the 4-octet-AS AS4_AGGREGATOR
     * @return the reconstructed AGGREGATOR
     */
    private static Aggregator mergeAggregator(Aggregator aggregator, Aggregator as4Aggregator) {
        if (aggregator.asn() == AsPathParser.AS_TRANS) {
            return as4Aggregator;
        }
        return aggregator;
    }

    /**
     * Parses the MP_REACH_NLRI attribute, capturing the NLRI as raw bytes (RFC 4760).
     *
     * <p>Reads AFI(2), SAFI(1), Next Hop Length(1), Next Hop(len), a reserved octet,
     * then the remaining value bytes verbatim as raw NLRI. The NLRI is not decoded here;
     * a family-specific decoder handles it.
     *
     * @param value a reader over the attribute value
     * @return the MP_REACH_NLRI attribute
     * @throws BmpParseException if the value is truncated
     */
    private static MpReachNlri parseMpReach(ByteReader value) {
        int afi = value.readUint16();
        int safi = value.readUint8();
        int nextHopLen = value.readUint8();
        byte[] nextHop = value.readBytes(nextHopLen);
        value.skip(1); // Reserved octet (RFC 4760 §3).
        byte[] nlri = value.readBytes(value.readableBytes());
        return new MpReachNlri(afi, safi, nextHop, nlri);
    }

    /**
     * Parses the MP_UNREACH_NLRI attribute, capturing the withdrawn NLRI as raw bytes
     * (RFC 4760).
     *
     * <p>Reads AFI(2), SAFI(1), then the remaining value bytes verbatim as raw
     * withdrawn NLRI. The NLRI is not decoded here.
     *
     * @param value a reader over the attribute value
     * @return the MP_UNREACH_NLRI attribute
     * @throws BmpParseException if the value is truncated
     */
    private static MpUnreachNlri parseMpUnreach(ByteReader value) {
        int afi = value.readUint16();
        int safi = value.readUint8();
        byte[] raw = value.readBytes(value.readableBytes());
        return new MpUnreachNlri(afi, safi, raw);
    }

    /**
     * Reads exactly four octets and builds an {@link Inet4Address}.
     *
     * @param value          a reader positioned at the address octets
     * @param attributeStart the absolute offset for diagnostics
     * @return the IPv4 address
     * @throws BmpParseException if fewer than four bytes remain or the bytes are invalid
     */
    private static Inet4Address readInet4(ByteReader value, int attributeStart) {
        byte[] bytes = value.readBytes(IPV4_ADDRESS_BYTES);
        try {
            return (Inet4Address) InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            // Only thrown for an illegal length, impossible with 4 bytes.
            throw new BmpParseException("Invalid IPv4 address bytes", attributeStart);
        }
    }

    /**
     * Validates that a declared length is a positive multiple of the per-element stride.
     *
     * @param length         the declared length
     * @param stride         the size of one element
     * @param what           the attribute name, for diagnostics
     * @param attributeStart the absolute offset for diagnostics
     * @throws BmpParseException if {@code length} is not a multiple of {@code stride}
     */
    private static void requireMultiple(int length, int stride, String what, int attributeStart) {
        if (length % stride != 0) {
            throw new BmpParseException(
                    what + " length " + length + " is not a multiple of " + stride, attributeStart);
        }
    }

    /**
     * Normalises an exception caught during attribute parsing into a
     * {@link BmpParseException}, preserving any existing one.
     *
     * @param e              the caught exception
     * @param attributeStart the absolute offset of the offending attribute
     * @return a {@link BmpParseException} describing the failure
     */
    private static BmpParseException asParseException(RuntimeException e, int attributeStart) {
        if (e instanceof BmpParseException bpe) {
            return bpe;
        }
        return new BmpParseException(
                "Malformed path attribute: " + e.getMessage(), attributeStart);
    }
}
