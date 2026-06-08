package it.lpworks.jbmp.protocol.builder;

import it.lpworks.jbmp.protocol.bgp.Aggregator;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AtomicAggregate;
import it.lpworks.jbmp.protocol.bgp.ClusterList;
import it.lpworks.jbmp.protocol.bgp.Communities;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunities;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunity;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bgp.LargeCommunities;
import it.lpworks.jbmp.protocol.bgp.LargeCommunity;
import it.lpworks.jbmp.protocol.bgp.LocalPref;
import it.lpworks.jbmp.protocol.bgp.MpReachNlri;
import it.lpworks.jbmp.protocol.bgp.MpUnreachNlri;
import it.lpworks.jbmp.protocol.bgp.MultiExitDisc;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginatorId;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.bgp.UnknownAttribute;
import it.lpworks.jbmp.protocol.io.ByteWriter;

import java.net.Inet4Address;
import java.util.List;
import java.util.Objects;

/**
 * Encodes a complete BGP-4 UPDATE message (RFC 4271 §4.3), the inverse of
 * {@link it.lpworks.jbmp.protocol.parser.bgp.BgpUpdateParser}.
 *
 * <p>The produced message is fully framed: a 16-octet marker of all-{@code 0xFF}
 * octets, a two-octet total length and a one-octet type ({@code 2}) (RFC 4271 §4.1),
 * followed by the body — a two-octet Withdrawn Routes Length and its prefixes, a
 * two-octet Total Path Attribute Length and its attributes, then the advertised NLRI
 * prefixes.
 *
 * <p>Each {@link PathAttribute} is encoded as the exact inverse of the parser's
 * dispatch. The attribute flags octet (RFC 4271 §4.3) is set to the RFC-mandated
 * O/T/P bits for each well-known or optional attribute, and the extended-length (E)
 * bit is set automatically whenever the attribute value exceeds 255 octets. AS_PATH
 * AS-number width is selected by {@code asPath2Byte}; the AGGREGATOR is encoded as six
 * octets when {@code asPath2Byte} is {@code true} and eight octets otherwise.
 * Prefixes use the length-prefixed encoding of RFC 4271 §4.3: a one-octet bit count
 * followed by {@code ceil(bits / 8)} significant octets.
 *
 * <p>This class is a stateless collection of static methods and cannot be
 * instantiated.
 */
public final class BgpUpdateBuilder {

    /** Length, in octets, of the BGP message marker (RFC 4271 §4.1). */
    private static final int MARKER_LENGTH = 16;

    /** The UPDATE message type code (RFC 4271 §4.1). */
    private static final int TYPE_UPDATE = 2;

    /** Marker octet value: every marker octet is {@code 0xFF} (RFC 4271 §4.1). */
    private static final int MARKER_OCTET = 0xFF;

    /** Extended-length (E) flag bit of the attribute flags octet (RFC 4271 §4.3). */
    private static final int FLAG_EXTENDED_LENGTH = 0x10;

    /** Optional (O) flag bit of the attribute flags octet (RFC 4271 §4.3). */
    private static final int FLAG_OPTIONAL = 0x80;

    /** Transitive (T) flag bit of the attribute flags octet (RFC 4271 §4.3). */
    private static final int FLAG_TRANSITIVE = 0x40;

    /** Partial (P) flag bit of the attribute flags octet (RFC 4271 §4.3). */
    private static final int FLAG_PARTIAL = 0x20;

    // Attribute type codes, mirrored from the parser.
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
    private static final int TYPE_LARGE_COMMUNITIES = 32;

    /** Threshold above which the extended-length encoding is required. */
    private static final int MAX_SINGLE_BYTE_LENGTH = 0xFF;

    /** Number of octets in an IPv4 address. */
    private static final int IPV4_ADDRESS_BYTES = 4;

    private BgpUpdateBuilder() {
        // Utility holder; not instantiable.
    }

    /**
     * Builds a complete, fully-framed BGP UPDATE message.
     *
     * @param withdrawn   the IPv4-unicast withdrawn routes (may be empty)
     * @param attributes  the path attributes in wire order (may be empty)
     * @param nlri        the IPv4-unicast advertised routes (may be empty)
     * @param asPath2Byte whether AS_PATH and AGGREGATOR are encoded with two-octet AS
     *                    numbers; when {@code false}, four-octet AS numbers are used
     * @return the encoded BGP UPDATE message, marker and header included
     * @throws NullPointerException if any list is {@code null}
     */
    public static byte[] update(List<IpPrefix> withdrawn, List<PathAttribute> attributes,
                                List<IpPrefix> nlri, boolean asPath2Byte) {
        Objects.requireNonNull(withdrawn, "withdrawn");
        Objects.requireNonNull(attributes, "attributes");
        Objects.requireNonNull(nlri, "nlri");

        ByteWriter writer = new ByteWriter();

        // --- BGP message header (RFC 4271 §4.1): marker(16), length(2), type(1). ---
        for (int i = 0; i < MARKER_LENGTH; i++) {
            writer.writeUint8(MARKER_OCTET);
        }
        int lengthIndex = writer.reserveUint16();
        writer.writeUint8(TYPE_UPDATE);

        // --- Withdrawn Routes (RFC 4271 §4.3): a 2-octet length + the prefixes. ---
        int withdrawnLenIndex = writer.reserveUint16();
        int withdrawnStart = writer.length();
        for (IpPrefix prefix : withdrawn) {
            writePrefix(writer, prefix);
        }
        writer.patchUint16(withdrawnLenIndex, writer.length() - withdrawnStart);

        // --- Total Path Attribute Length (RFC 4271 §4.3) + the attributes. ---
        int pathAttrLenIndex = writer.reserveUint16();
        int pathAttrStart = writer.length();
        for (PathAttribute attribute : attributes) {
            writeAttribute(writer, attribute, asPath2Byte);
        }
        writer.patchUint16(pathAttrLenIndex, writer.length() - pathAttrStart);

        // --- NLRI (RFC 4271 §4.3): the remaining body octets. ---
        for (IpPrefix prefix : nlri) {
            writePrefix(writer, prefix);
        }

        writer.patchUint16(lengthIndex, writer.length());
        return writer.toByteArray();
    }

    // ------------------------------------------------------------------
    // Path attribute encoding
    // ------------------------------------------------------------------

    /**
     * Encodes a single path attribute (flags, type code, length, value).
     *
     * @param writer      the destination writer
     * @param attribute   the attribute to encode
     * @param asPath2Byte whether AS_PATH/AGGREGATOR use two-octet AS numbers
     */
    private static void writeAttribute(ByteWriter writer, PathAttribute attribute,
                                       boolean asPath2Byte) {
        switch (attribute) {
            case Origin origin -> writeTlv(writer, FLAG_TRANSITIVE, TYPE_ORIGIN,
                    encodeOrigin(origin));
            case AsPath asPath -> writeTlv(writer, FLAG_TRANSITIVE, TYPE_AS_PATH,
                    encodeAsPath(asPath, asPath2Byte));
            case NextHop nextHop -> writeTlv(writer, FLAG_TRANSITIVE, TYPE_NEXT_HOP,
                    encodeAddress(nextHop.address()));
            case MultiExitDisc med -> writeTlv(writer, FLAG_OPTIONAL, TYPE_MULTI_EXIT_DISC,
                    encodeUint32(med.med()));
            case LocalPref localPref -> writeTlv(writer, FLAG_TRANSITIVE, TYPE_LOCAL_PREF,
                    encodeUint32(localPref.localPreference()));
            case AtomicAggregate ignored -> writeTlv(writer, FLAG_TRANSITIVE,
                    TYPE_ATOMIC_AGGREGATE, new byte[0]);
            case Aggregator aggregator -> writeTlv(writer, FLAG_OPTIONAL | FLAG_TRANSITIVE,
                    TYPE_AGGREGATOR, encodeAggregator(aggregator, asPath2Byte));
            case Communities communities -> writeTlv(writer, FLAG_OPTIONAL | FLAG_TRANSITIVE,
                    TYPE_COMMUNITIES, encodeCommunities(communities));
            case OriginatorId originatorId -> writeTlv(writer, FLAG_OPTIONAL, TYPE_ORIGINATOR_ID,
                    encodeAddress(originatorId.id()));
            case ClusterList clusterList -> writeTlv(writer, FLAG_OPTIONAL, TYPE_CLUSTER_LIST,
                    encodeClusterList(clusterList));
            case ExtendedCommunities ext -> writeTlv(writer, FLAG_OPTIONAL | FLAG_TRANSITIVE,
                    TYPE_EXTENDED_COMMUNITIES, encodeExtendedCommunities(ext));
            case LargeCommunities large -> writeTlv(writer, FLAG_OPTIONAL | FLAG_TRANSITIVE,
                    TYPE_LARGE_COMMUNITIES, encodeLargeCommunities(large));
            case MpReachNlri mpReach -> writeTlv(writer, FLAG_OPTIONAL, TYPE_MP_REACH_NLRI,
                    encodeMpReach(mpReach));
            case MpUnreachNlri mpUnreach -> writeTlv(writer, FLAG_OPTIONAL, TYPE_MP_UNREACH_NLRI,
                    encodeMpUnreach(mpUnreach));
            case UnknownAttribute unknown -> writeUnknown(writer, unknown);
        }
    }

    /**
     * Writes the generic attribute framing: flags, type code, length and value.
     *
     * <p>The extended-length (E) flag is added automatically when the value exceeds
     * {@value #MAX_SINGLE_BYTE_LENGTH} octets (RFC 4271 §4.3).
     *
     * @param writer    the destination writer
     * @param baseFlags the O/T/P flag bits for this attribute (without the E bit)
     * @param typeCode  the attribute type code
     * @param value     the already-encoded attribute value
     */
    private static void writeTlv(ByteWriter writer, int baseFlags, int typeCode, byte[] value) {
        boolean extended = value.length > MAX_SINGLE_BYTE_LENGTH;
        int flags = extended ? (baseFlags | FLAG_EXTENDED_LENGTH) : baseFlags;
        writer.writeUint8(flags);
        writer.writeUint8(typeCode);
        if (extended) {
            writer.writeUint16(value.length);
        } else {
            writer.writeUint8(value.length);
        }
        writer.writeBytes(value);
    }

    /**
     * Encodes an {@link UnknownAttribute} verbatim, honouring its stored flags and the
     * automatic extended-length promotion.
     *
     * @param writer  the destination writer
     * @param unknown the unknown attribute to encode
     */
    private static void writeUnknown(ByteWriter writer, UnknownAttribute unknown) {
        int baseFlags = 0;
        if (unknown.flags().optional()) {
            baseFlags |= FLAG_OPTIONAL;
        }
        if (unknown.flags().transitive()) {
            baseFlags |= FLAG_TRANSITIVE;
        }
        if (unknown.flags().partial()) {
            baseFlags |= FLAG_PARTIAL;
        }
        writeTlv(writer, baseFlags, unknown.typeCode(), unknown.value());
    }

    /**
     * Encodes the ORIGIN attribute value: a single origin-type octet (RFC 4271 §5.1.1).
     *
     * @param origin the ORIGIN attribute
     * @return the one-octet value
     */
    private static byte[] encodeOrigin(Origin origin) {
        ByteWriter w = new ByteWriter(1);
        w.writeUint8(origin.value().code());
        return w.toByteArray();
    }

    /**
     * Encodes an AS_PATH value as a sequence of segments (RFC 4271 §4.3 / RFC 5065).
     *
     * <p>Each segment is a one-octet type, a one-octet AS count, then the AS numbers
     * at the configured width (two or four octets each).
     *
     * @param asPath      the AS_PATH attribute
     * @param asPath2Byte whether to use two-octet AS numbers
     * @return the encoded value
     */
    private static byte[] encodeAsPath(AsPath asPath, boolean asPath2Byte) {
        ByteWriter w = new ByteWriter();
        for (AsPathSegment segment : asPath.segments()) {
            long[] asns = segment.asns();
            w.writeUint8(segment.type().code());
            w.writeUint8(asns.length);
            for (long asn : asns) {
                if (asPath2Byte) {
                    w.writeUint16((int) (asn & 0xFFFF));
                } else {
                    w.writeUint32(asn);
                }
            }
        }
        return w.toByteArray();
    }

    /**
     * Encodes an AGGREGATOR value (RFC 4271 §5.1.7, RFC 6793): the AS number at the
     * configured width followed by the 4-octet IPv4 address.
     *
     * @param aggregator  the AGGREGATOR attribute
     * @param asPath2Byte whether to use a two-octet AS number (six-octet value) or a
     *                    four-octet AS number (eight-octet value)
     * @return the encoded value
     */
    private static byte[] encodeAggregator(Aggregator aggregator, boolean asPath2Byte) {
        ByteWriter w = new ByteWriter(8);
        if (asPath2Byte) {
            w.writeUint16((int) (aggregator.asn() & 0xFFFF));
        } else {
            w.writeUint32(aggregator.asn());
        }
        w.writeBytes(aggregator.address().getAddress());
        return w.toByteArray();
    }

    /**
     * Encodes a COMMUNITIES value: each community as a 4-octet value (RFC 1997).
     *
     * @param communities the COMMUNITIES attribute
     * @return the encoded value
     */
    private static byte[] encodeCommunities(Communities communities) {
        int[] values = communities.values();
        ByteWriter w = new ByteWriter(values.length * 4);
        for (int value : values) {
            w.writeUint32(value & 0xFFFFFFFFL);
        }
        return w.toByteArray();
    }

    /**
     * Encodes a CLUSTER_LIST value: each CLUSTER_ID as a 4-octet IPv4 address
     * (RFC 4456).
     *
     * @param clusterList the CLUSTER_LIST attribute
     * @return the encoded value
     */
    private static byte[] encodeClusterList(ClusterList clusterList) {
        List<Inet4Address> ids = clusterList.clusterIds();
        ByteWriter w = new ByteWriter(ids.size() * IPV4_ADDRESS_BYTES);
        for (Inet4Address id : ids) {
            w.writeBytes(id.getAddress());
        }
        return w.toByteArray();
    }

    /**
     * Encodes an EXTENDED COMMUNITIES value: each community as 8 octets (RFC 4360).
     *
     * @param ext the EXTENDED COMMUNITIES attribute
     * @return the encoded value
     */
    private static byte[] encodeExtendedCommunities(ExtendedCommunities ext) {
        List<ExtendedCommunity> communities = ext.communities();
        ByteWriter w = new ByteWriter(communities.size() * 8);
        for (ExtendedCommunity community : communities) {
            w.writeBytes(community.value());
        }
        return w.toByteArray();
    }

    /**
     * Encodes a LARGE COMMUNITIES value: each community as three 4-octet fields
     * (RFC 8092).
     *
     * @param large the LARGE COMMUNITIES attribute
     * @return the encoded value
     */
    private static byte[] encodeLargeCommunities(LargeCommunities large) {
        List<LargeCommunity> communities = large.communities();
        ByteWriter w = new ByteWriter(communities.size() * 12);
        for (LargeCommunity community : communities) {
            w.writeUint32(community.globalAdministrator());
            w.writeUint32(community.localData1());
            w.writeUint32(community.localData2());
        }
        return w.toByteArray();
    }

    /**
     * Encodes an MP_REACH_NLRI value (RFC 4760 §3): AFI(2), SAFI(1), Next Hop
     * Length(1), the next-hop bytes, a reserved octet, then the raw NLRI bytes.
     *
     * @param mpReach the MP_REACH_NLRI attribute
     * @return the encoded value
     */
    private static byte[] encodeMpReach(MpReachNlri mpReach) {
        byte[] nextHop = mpReach.nextHop();
        byte[] nlri = mpReach.nlri();
        ByteWriter w = new ByteWriter();
        w.writeUint16(mpReach.afi());
        w.writeUint8(mpReach.safi());
        w.writeUint8(nextHop.length);
        w.writeBytes(nextHop);
        w.writeUint8(0); // Reserved octet (RFC 4760 §3).
        w.writeBytes(nlri);
        return w.toByteArray();
    }

    /**
     * Encodes an MP_UNREACH_NLRI value (RFC 4760 §4): AFI(2), SAFI(1), then the raw
     * withdrawn-NLRI bytes.
     *
     * @param mpUnreach the MP_UNREACH_NLRI attribute
     * @return the encoded value
     */
    private static byte[] encodeMpUnreach(MpUnreachNlri mpUnreach) {
        byte[] withdrawn = mpUnreach.withdrawnNlri();
        ByteWriter w = new ByteWriter();
        w.writeUint16(mpUnreach.afi());
        w.writeUint8(mpUnreach.safi());
        w.writeBytes(withdrawn);
        return w.toByteArray();
    }

    /**
     * Encodes a 4-octet IPv4 address from an {@link Inet4Address}.
     *
     * @param address the IPv4 address
     * @return the 4 raw address octets
     */
    private static byte[] encodeAddress(java.net.InetAddress address) {
        return address.getAddress();
    }

    /**
     * Encodes an unsigned 32-bit value as 4 octets, big-endian.
     *
     * @param value the value, in {@code [0, 4294967295]}
     * @return the 4-octet encoding
     */
    private static byte[] encodeUint32(long value) {
        ByteWriter w = new ByteWriter(4);
        w.writeUint32(value);
        return w.toByteArray();
    }

    // ------------------------------------------------------------------
    // Prefix encoding (RFC 4271 §4.3)
    // ------------------------------------------------------------------

    /**
     * Writes an IPv4 prefix using the length-prefixed encoding (RFC 4271 §4.3): a
     * one-octet prefix-length in bits followed by {@code ceil(bits / 8)} significant
     * address octets.
     *
     * @param writer the destination writer
     * @param prefix the prefix to encode
     */
    private static void writePrefix(ByteWriter writer, IpPrefix prefix) {
        int bits = prefix.prefixLength();
        int significantBytes = (bits + 7) / 8;
        byte[] address = prefix.address().getAddress();
        writer.writeUint8(bits);
        writer.writeBytes(address, 0, significantBytes);
    }
}
