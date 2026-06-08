package it.lpworks.jbmp.mock;

import it.lpworks.jbmp.protocol.bgp.Aggregator;
import it.lpworks.jbmp.protocol.bgp.AddressFamily;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AsPathSegmentType;
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
import it.lpworks.jbmp.protocol.bgp.MultiExitDisc;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginType;
import it.lpworks.jbmp.protocol.bgp.OriginatorId;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.io.ByteWriter;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.SplittableRandom;

/**
 * Builds the full, production-grade path-attribute set carried by a single mock BGP
 * UPDATE announcement, and — for a small fraction of announcements — multiprotocol
 * (MP-BGP) reachability for the EVPN, Flow Specification, SR Policy, BGP-LS and L3VPN
 * address families.
 *
 * <p>A real BMP feed from a production router carries far more than ORIGIN, AS_PATH and
 * a NEXT_HOP: it carries multi-segment AS_PATHs (RFC 4271 §5.1.2, RFC 5065), MULTI_EXIT_DISC
 * and LOCAL_PREF (RFC 4271 §5.1.4 / §5.1.5), ATOMIC_AGGREGATE and AGGREGATOR
 * (RFC 4271 §5.1.6 / §5.1.7), standard, large and extended communities
 * (RFC 1997, RFC 8092, RFC 4360 — the last including L3VPN Route Targets), route-reflector
 * attributes (ORIGINATOR_ID and CLUSTER_LIST, RFC 4456) and a long tail of multiprotocol
 * families (RFC 4760). This mixer reproduces that richness so jBMP's own end-to-end
 * pipeline exercises every structured column rather than only the basics.
 *
 * <p><strong>Determinism.</strong> The generator must remain a pure function of its
 * inputs so the exact byte stream can be unit-tested by parsing it back. Every random
 * choice is therefore drawn from a {@link SplittableRandom} seeded from the
 * {@code (routerIndex, peerIndex, prefixIndex)} triple, so the same triple always yields
 * the same attributes. The first prefix of every peer ({@code prefixIndex == 0}) is
 * pinned to a fixed, "vanilla" IPv4-unicast attribute set (ORIGIN=IGP, a three-AS
 * AS_SEQUENCE, NEXT_HOP, MED, LOCAL_PREF=100 and COMMUNITIES) so that callers and tests
 * have a stable, well-known baseline route.
 *
 * <p>All addresses and AS numbers are drawn from the documentation ranges of RFC 5737
 * (IPv4) and RFC 5398 (AS numbers); no real network is referenced.
 *
 * <p>Instances are cheap and stateless beyond the immutable configuration; a single
 * instance may be shared across a whole session.
 */
final class AttributeMixer {

    // ------------------------------------------------------------------
    // Documentation-range constants (RFC 5398 / RFC 5737)
    // ------------------------------------------------------------------

    /** First reserved-for-documentation 32-bit AS number (RFC 5398: 4200000000). */
    private static final long ASN_DOC_BASE = 4_200_000_000L;

    /** Lowest reserved-for-documentation 16-bit AS number (RFC 5398: 64496). */
    private static final long ASN_DOC_16_BASE = 64_496L;

    /** Highest reserved-for-documentation 16-bit AS number (RFC 5398: 64511). */
    private static final long ASN_DOC_16_TOP = 64_511L;

    /** Transit AS prepended near the head of a typical AS_PATH (documentation range). */
    private static final long TRANSIT_ASN = 65_550L;

    /** Upstream AS at the very head of a typical AS_PATH (documentation range). */
    private static final long UPSTREAM_ASN = 65_540L;

    /** Next-hop address used for IPv4-unicast advertisements (RFC 5737 TEST-NET-1 host). */
    private static final String NEXT_HOP_V4 = "192.0.2.254";

    /** Cluster-ID base address for route-reflector CLUSTER_LIST entries (RFC 5737). */
    private static final int CLUSTER_ID_NET = 0xC0_00_02_00; // 192.0.2.0/24

    /** RFC 5737 TEST-NET-1 base, used as the originator-ID / RR-client identifier. */
    private static final int ORIGINATOR_NET = 0xC0_00_02_00; // 192.0.2.0/24

    // ------------------------------------------------------------------
    // Well-known communities and extended-community type bytes
    // ------------------------------------------------------------------

    /** NO_EXPORT well-known community (RFC 1997: 0xFFFFFF01). */
    private static final int COMMUNITY_NO_EXPORT = 0xFFFF_FF01;

    /** High-order type octet for a two-octet-AS transitive extended community (RFC 4360). */
    private static final int EXT_TYPE_2OCTET_AS = 0x00;

    /** High-order type octet for an IPv4-address transitive extended community (RFC 4360). */
    private static final int EXT_TYPE_IPV4 = 0x01;

    /** Route Target sub-type octet (RFC 4360 §4 / RFC 4364). */
    private static final int EXT_SUBTYPE_ROUTE_TARGET = 0x02;

    /** Route Origin (SoO) sub-type octet (RFC 4360 §4). */
    private static final int EXT_SUBTYPE_ROUTE_ORIGIN = 0x03;

    // ------------------------------------------------------------------
    // Probabilities and bounds for the randomised mix
    // ------------------------------------------------------------------

    /** Fraction of announcements that additionally carry ATOMIC_AGGREGATE + AGGREGATOR. */
    private static final double P_AGGREGATOR = 0.20;

    /** Fraction of announcements that additionally carry ORIGINATOR_ID + CLUSTER_LIST. */
    private static final double P_ROUTE_REFLECTOR = 0.25;

    /** Probability an AS_PATH ends with a small AS_SET segment (RFC 4271 §5.1.2). */
    private static final double P_AS_SET = 0.12;

    /** Probability an AS_PATH contains an AS_CONFED_SEQUENCE segment (RFC 5065). */
    private static final double P_AS_CONFED = 0.08;

    /** Maximum number of standard communities attached (RFC 1997). */
    private static final int MAX_STD_COMMUNITIES = 4;

    /** Maximum number of large communities attached (RFC 8092). */
    private static final int MAX_LARGE_COMMUNITIES = 2;

    /** Maximum number of extended communities attached to a non-VPN route (RFC 4360). */
    private static final int MAX_EXT_COMMUNITIES = 2;

    /** Largest representable unsigned 32-bit value. */
    private static final long MAX_UINT32 = 0xFFFF_FFFFL;

    // ------------------------------------------------------------------
    // Multiprotocol-family selection (every 1-in-N announcements)
    // ------------------------------------------------------------------

    /**
     * Spacing of the multiprotocol mix: for prefix indices that are positive multiples of
     * this value the announcement is emitted as an MP-BGP route of a family chosen by the
     * multiple, rather than as a plain IPv4-unicast route. The value is small enough that
     * the default {@code stress} dump (1000 prefixes/peer) covers every family many times,
     * yet the families never collide with {@code prefixIndex == 0}, which stays vanilla.
     */
    private static final int MP_EVERY = 17;

    /** The L3VPN MPLS-VPN MP-BGP family is sampled at this residue (RFC 4364). */
    private static final int MP_SLOT_L3VPN = 0;

    /** The EVPN MP-BGP family is sampled at this residue (RFC 7432). */
    private static final int MP_SLOT_EVPN = 1;

    /** The Flow Specification MP-BGP family is sampled at this residue (RFC 8955). */
    private static final int MP_SLOT_FLOWSPEC = 2;

    /** The SR Policy MP-BGP family is sampled at this residue. */
    private static final int MP_SLOT_SR_POLICY = 3;

    /** The BGP-LS MP-BGP family is sampled at this residue (RFC 7752). */
    private static final int MP_SLOT_BGP_LS = 4;

    /** Number of distinct multiprotocol families in the rotation. */
    private static final int MP_SLOTS = 5;

    private final boolean fullMix;

    /**
     * Creates a mixer.
     *
     * @param fullMix when {@code true}, the mixer additionally emits the multiprotocol
     *                families (L3VPN, EVPN, Flow Specification, SR Policy, BGP-LS) on a
     *                deterministic fraction of announcements; when {@code false}, every
     *                announcement is a richly-attributed IPv4-unicast route and no
     *                multiprotocol families are produced
     */
    AttributeMixer(boolean fullMix) {
        this.fullMix = fullMix;
    }

    /**
     * Builds one announcement for the given prefix, returning the path attributes in wire
     * order together with the IPv4-unicast NLRI list to advertise.
     *
     * <p>For a plain IPv4-unicast route the returned NLRI list holds the supplied
     * {@code prefix} and the reachability lives in the NEXT_HOP attribute. For a
     * multiprotocol route the NLRI list is empty and reachability is carried inside an
     * {@link MpReachNlri} attribute (RFC 4760); the {@code prefix} still seeds the route's
     * addressing so successive announcements differ.
     *
     * @param routerIndex the zero-based router index (seeds the RNG and derives ASNs)
     * @param peerIndex   the zero-based peer index within the router
     * @param prefixIndex the zero-based prefix ordinal within the peer's dump
     * @param originAsn   the peer's origin AS number (an unsigned 32-bit documentation ASN)
     * @param prefix      the IPv4-unicast prefix this announcement is built around
     * @return the assembled announcement (attributes plus IPv4-unicast NLRI)
     */
    Announcement build(int routerIndex, int peerIndex, int prefixIndex, long originAsn,
                       IpPrefix prefix) {
        // Pin the very first prefix of every peer to a stable, vanilla baseline so callers
        // and tests have a deterministic, well-known reference route.
        if (prefixIndex == 0) {
            return vanilla(originAsn, peerIndex, prefixIndex, prefix);
        }

        SplittableRandom rng = seededRandom(routerIndex, peerIndex, prefixIndex);

        if (fullMix && prefixIndex % MP_EVERY == 0) {
            return multiprotocol(rng, prefixIndex, originAsn, prefix);
        }
        return ipv4Unicast(rng, peerIndex, prefixIndex, originAsn, prefix);
    }

    // ------------------------------------------------------------------
    // IPv4-unicast announcements
    // ------------------------------------------------------------------

    /**
     * Builds the fixed baseline IPv4-unicast attribute set: ORIGIN=IGP, a three-AS
     * AS_SEQUENCE (upstream, transit, origin), NEXT_HOP, a small MED, LOCAL_PREF=100 and a
     * pair of COMMUNITIES. This matches the historical mock baseline exactly.
     *
     * @param originAsn   the peer's origin ASN
     * @param peerIndex   the peer index, mixed into the community value half
     * @param prefixIndex the prefix ordinal, mixed into the MED
     * @param prefix      the advertised prefix
     * @return the baseline announcement
     */
    private Announcement vanilla(long originAsn, int peerIndex, int prefixIndex, IpPrefix prefix) {
        List<PathAttribute> attributes = List.of(
                new Origin(OriginType.IGP),
                new AsPath(List.of(new AsPathSegment(AsPathSegmentType.AS_SEQUENCE,
                        new long[] {UPSTREAM_ASN, TRANSIT_ASN, originAsn}))),
                new NextHop(v4(NEXT_HOP_V4)),
                new MultiExitDisc(prefixIndex % 100),
                new LocalPref(100L),
                new Communities(new int[] {community(originAsn, peerIndex), COMMUNITY_NO_EXPORT}));
        return new Announcement(attributes, List.of(prefix));
    }

    /**
     * Builds a richly-attributed IPv4-unicast announcement: a multi-segment AS_PATH with
     * realistic ASNs, ORIGIN, NEXT_HOP, MED and LOCAL_PREF, a randomised mix of standard,
     * large and extended communities, an optional ATOMIC_AGGREGATE + AGGREGATOR pair, and
     * optional route-reflector attributes (ORIGINATOR_ID + CLUSTER_LIST).
     *
     * <p>The attribute order follows ascending type code, the canonical order a speaker
     * emits (RFC 4271 §4.3 does not mandate an order, but ascending type code is the de
     * facto convention).
     *
     * @param rng         the per-prefix deterministic RNG
     * @param peerIndex   the peer index
     * @param prefixIndex the prefix ordinal
     * @param originAsn   the peer's origin ASN
     * @param prefix      the advertised prefix
     * @return the assembled IPv4-unicast announcement
     */
    private Announcement ipv4Unicast(SplittableRandom rng, int peerIndex, int prefixIndex,
                                     long originAsn, IpPrefix prefix) {
        List<PathAttribute> attributes = new ArrayList<>();
        attributes.add(new Origin(originType(rng)));               // type 1
        attributes.add(asPath(rng, originAsn));                    // type 2
        attributes.add(new NextHop(v4(NEXT_HOP_V4)));              // type 3
        attributes.add(new MultiExitDisc(prefixIndex % 1000));     // type 4
        attributes.add(new LocalPref(localPref(rng)));             // type 5

        boolean aggregator = rng.nextDouble() < P_AGGREGATOR;
        if (aggregator) {
            attributes.add(new AtomicAggregate());                 // type 6
            attributes.add(new Aggregator(aggregatorAsn(rng),      // type 7
                    v4FromInt(CLUSTER_ID_NET | (1 + rng.nextInt(254)))));
        }

        addStandardCommunities(rng, originAsn, attributes);        // type 8
        if (rng.nextDouble() < P_ROUTE_REFLECTOR) {
            attributes.add(new OriginatorId(                       // type 9
                    v4FromInt(ORIGINATOR_NET | (1 + rng.nextInt(254)))));
            attributes.add(clusterList(rng));                      // type 10
        }
        addExtendedCommunities(rng, originAsn, false, attributes); // type 16
        addLargeCommunities(rng, originAsn, attributes);           // type 32

        return new Announcement(List.copyOf(attributes), List.of(prefix));
    }

    // ------------------------------------------------------------------
    // Multiprotocol announcements (RFC 4760)
    // ------------------------------------------------------------------

    /**
     * Builds a multiprotocol announcement for one of the rarer families, chosen
     * deterministically from {@code prefixIndex}. The route is carried entirely inside an
     * {@link MpReachNlri} attribute (RFC 4760) and the IPv4-unicast NLRI list is empty.
     *
     * <p>Every family still carries the mandatory ORIGIN and AS_PATH plus a realistic
     * community mix; the L3VPN family additionally carries a Route Target extended
     * community (RFC 4364 §4.3.1), as a real VPN route must.
     *
     * @param rng         the per-prefix deterministic RNG
     * @param prefixIndex the prefix ordinal (selects the family)
     * @param originAsn   the peer's origin ASN
     * @param prefix      the prefix this route is built around (seeds the addressing)
     * @return the assembled multiprotocol announcement
     */
    private Announcement multiprotocol(SplittableRandom rng, int prefixIndex, long originAsn,
                                       IpPrefix prefix) {
        int slot = (prefixIndex / MP_EVERY) % MP_SLOTS;
        List<PathAttribute> attributes = new ArrayList<>();
        attributes.add(new Origin(originType(rng)));
        attributes.add(asPath(rng, originAsn));

        MpReachNlri mpReach = switch (slot) {
            case MP_SLOT_L3VPN -> {
                // A real L3VPN route is identified by its Route Target (RFC 4364 §4.3.1).
                attributes.add(routeTargetExtCommunities(rng, originAsn));
                yield l3vpnReach(originAsn, prefix);
            }
            case MP_SLOT_EVPN -> evpnReach(rng, originAsn, prefix);
            case MP_SLOT_FLOWSPEC -> flowSpecReach(prefix);
            case MP_SLOT_SR_POLICY -> srPolicyReach(rng, originAsn, prefix);
            case MP_SLOT_BGP_LS -> bgpLsReach(rng, originAsn);
            default -> throw new IllegalStateException("Unreachable MP slot: " + slot);
        };

        addStandardCommunities(rng, originAsn, attributes);
        attributes.add(mpReach);
        addLargeCommunities(rng, originAsn, attributes);

        // Multiprotocol reachability lives in the attribute; no IPv4-unicast NLRI.
        return new Announcement(List.copyOf(attributes), List.of());
    }

    /**
     * Builds an MPLS-L3VPN (AFI IPv4, SAFI 128) MP_REACH_NLRI (RFC 4364, RFC 8277).
     *
     * <p>The next hop is a VPN-IPv4 next hop: an 8-octet zero Route Distinguisher followed
     * by the 4-octet IPv4 next-hop address (RFC 4364 §4.3.2). The NLRI is a single VPN-IPv4
     * route: a 1-octet length in bits, a 3-octet MPLS label with the bottom-of-stack bit
     * set (RFC 3032 / RFC 8277), the 8-octet Route Distinguisher and the significant
     * prefix octets (RFC 4364 §4.3.4).
     *
     * @param originAsn the origin ASN, used to build a type-0 Route Distinguisher
     * @param prefix    the inner IPv4 prefix
     * @return the L3VPN MP_REACH_NLRI attribute
     */
    private MpReachNlri l3vpnReach(long originAsn, IpPrefix prefix) {
        byte[] rd = routeDistinguisher(originAsn);
        byte[] addr = prefix.address().getAddress();
        int prefixBits = prefix.prefixLength();
        int significant = (prefixBits + 7) / 8;

        // VPN-IPv4 next hop: 8-octet RD (zero) + 4-octet IPv4 next hop (RFC 4364 §4.3.2).
        ByteWriter nh = new ByteWriter(12);
        nh.writeUint64(0L);
        nh.writeBytes(v4(NEXT_HOP_V4).getAddress());

        // Label (20 bits) with the bottom-of-stack bit set, per RFC 3032 §2.1.
        int label = 0x10; // arbitrary documentation label value
        byte[] labelBytes = {
                (byte) (label >>> 12),
                (byte) (label >>> 4),
                (byte) (((label & 0x0F) << 4) | 0x01)}; // S-bit set
        int totalBits = (labelBytes.length * 8) + (rd.length * 8) + prefixBits;

        ByteWriter nlri = new ByteWriter();
        nlri.writeUint8(totalBits);
        nlri.writeBytes(labelBytes);
        nlri.writeBytes(rd);
        nlri.writeBytes(addr, 0, significant);

        return new MpReachNlri(AddressFamily.AFI_IPV4, AddressFamily.SAFI_MPLS_VPN,
                nh.toByteArray(), nlri.toByteArray());
    }

    /**
     * Builds an EVPN (AFI 25, SAFI 70) MAC/IP Advertisement route (type 2) MP_REACH_NLRI
     * (RFC 7432 §7.2).
     *
     * <p>The route value is a Route Distinguisher (8 octets), a 10-octet Ethernet Segment
     * Identifier, a 4-octet Ethernet Tag ID, a 1-octet MAC Address Length (48), a 6-octet
     * MAC address, a 1-octet IP Address Length (0 — MAC-only) and a 3-octet MPLS Label1.
     * The next hop is the 4-octet IPv4 next-hop address (RFC 7432 §7.2).
     *
     * @param rng       the deterministic RNG, used to vary the MAC address
     * @param originAsn the origin ASN, used to build the Route Distinguisher
     * @param prefix    the prefix this route is built around (seeds the Ethernet Tag)
     * @return the EVPN MP_REACH_NLRI attribute
     */
    private MpReachNlri evpnReach(SplittableRandom rng, long originAsn, IpPrefix prefix) {
        byte[] rd = routeDistinguisher(originAsn);
        byte[] mac = new byte[6];
        rng.nextBytes(mac);
        mac[0] = (byte) ((mac[0] & 0xFE) | 0x02); // locally administered, unicast.
        int ethernetTag = prefix.address().getAddress()[3] & 0xFF;

        ByteWriter route = new ByteWriter();
        route.writeBytes(rd);                       // Route Distinguisher (8).
        route.writeUint64(0L);                      // Ethernet Segment Identifier (10): hi 8.
        route.writeUint16(0);                       // Ethernet Segment Identifier: lo 2.
        route.writeUint32(ethernetTag);             // Ethernet Tag ID (4).
        route.writeUint8(48);                       // MAC Address Length, in bits.
        route.writeBytes(mac);                      // MAC address (6).
        route.writeUint8(0);                        // IP Address Length: 0 (MAC-only).
        // MPLS Label1 (3 octets), bottom-of-stack set (RFC 7432 §7.2).
        route.writeUint8(0x00);
        route.writeUint8(0x10);
        route.writeUint8(0x01);
        byte[] routeValue = route.toByteArray();

        ByteWriter nlri = new ByteWriter();
        nlri.writeUint8(2);                         // EVPN Route Type 2 (MAC/IP).
        nlri.writeUint8(routeValue.length);         // Route length.
        nlri.writeBytes(routeValue);

        return new MpReachNlri(AddressFamily.AFI_L2VPN, AddressFamily.SAFI_EVPN,
                v4(NEXT_HOP_V4).getAddress(), nlri.toByteArray());
    }

    /**
     * Builds an IPv4 Flow Specification (AFI IPv4, SAFI 133) MP_REACH_NLRI (RFC 8955 §4).
     *
     * <p>The rule matches a destination-prefix (component type 1) and an IP-protocol equal
     * to 6/TCP (numeric component type 3, RFC 8955 §4.2.1.1–§4.2.1.3). Flow Specification
     * uses no next hop (the rule is the reachability), so the next-hop field is empty
     * (RFC 8955 §4).
     *
     * @param prefix the destination prefix the rule matches
     * @return the Flow Specification MP_REACH_NLRI attribute
     */
    private MpReachNlri flowSpecReach(IpPrefix prefix) {
        int prefixBits = prefix.prefixLength();
        int significant = (prefixBits + 7) / 8;
        byte[] addr = prefix.address().getAddress();

        ByteWriter rule = new ByteWriter();
        // Component 1: Destination Prefix (RFC 8955 §4.2.1.2).
        rule.writeUint8(1);
        rule.writeUint8(prefixBits);
        rule.writeBytes(addr, 0, significant);
        // Component 3: IP Protocol == 6 (TCP). One {op, value} pair, end-of-list +
        // equal, value length 1 octet (RFC 8955 §4.2.1.1 / §4.2.1.3).
        rule.writeUint8(3);
        rule.writeUint8(0x81);   // EOL (0x80) | EQ (0x01), len bits 00 -> 1-octet value.
        rule.writeUint8(6);      // TCP.
        byte[] ruleBytes = rule.toByteArray();

        // NLRI length prefix: 1 octet when < 0xF0 (RFC 8955 §4).
        ByteWriter nlri = new ByteWriter();
        nlri.writeUint8(ruleBytes.length);
        nlri.writeBytes(ruleBytes);

        return new MpReachNlri(AddressFamily.AFI_IPV4, AddressFamily.SAFI_FLOWSPEC,
                new byte[0], nlri.toByteArray());
    }

    /**
     * Builds a Segment Routing Policy (AFI IPv4, SAFI 73) MP_REACH_NLRI
     * (draft-ietf-idr-segment-routing-te-policy).
     *
     * <p>The NLRI encodes a 1-octet NLRI length (in bits), a 4-octet distinguisher, a
     * 4-octet policy colour and the 4-octet IPv4 endpoint address. The next hop is the
     * 4-octet IPv4 next hop.
     *
     * @param rng       the deterministic RNG, used to vary the colour
     * @param originAsn the origin ASN (unused beyond family selection but kept for symmetry)
     * @param prefix    the prefix whose address supplies the SR-policy endpoint
     * @return the SR Policy MP_REACH_NLRI attribute
     */
    private MpReachNlri srPolicyReach(SplittableRandom rng, long originAsn, IpPrefix prefix) {
        long colour = 100L + rng.nextInt(900);
        byte[] endpoint = prefix.address().getAddress();

        ByteWriter body = new ByteWriter();
        body.writeUint32(1L);            // Distinguisher.
        body.writeUint32(colour);        // Policy colour.
        body.writeBytes(endpoint);       // IPv4 endpoint (4 octets).
        byte[] bodyBytes = body.toByteArray();

        ByteWriter nlri = new ByteWriter();
        nlri.writeUint8(bodyBytes.length * 8); // NLRI length, in bits.
        nlri.writeBytes(bodyBytes);

        return new MpReachNlri(AddressFamily.AFI_IPV4, AddressFamily.SAFI_SR_POLICY,
                v4(NEXT_HOP_V4).getAddress(), nlri.toByteArray());
    }

    /**
     * Builds a BGP Link-State (AFI 16388, SAFI 71) Node-NLRI MP_REACH_NLRI (RFC 7752 §3.2).
     *
     * <p>The NLRI is a Node NLRI (type 1): a 2-octet NLRI Type, a 2-octet Total NLRI
     * Length, a 1-octet Protocol-ID, an 8-octet Identifier, and a Local Node Descriptors
     * TLV (type 256) carrying an Autonomous System descriptor (sub-TLV 512) set to the
     * origin AS (RFC 7752 §3.2.1.2 / §3.3.1.1). BGP-LS uses a next hop, encoded here as the
     * 4-octet IPv4 next hop.
     *
     * @param rng       the deterministic RNG (unused; kept for signature symmetry)
     * @param originAsn the origin ASN advertised in the AS node descriptor
     * @return the BGP-LS MP_REACH_NLRI attribute
     */
    private MpReachNlri bgpLsReach(SplittableRandom rng, long originAsn) {
        // Local Node Descriptors TLV (type 256) -> AS sub-TLV (type 512), 4-octet AS.
        ByteWriter asSubTlv = new ByteWriter();
        asSubTlv.writeUint16(512);            // Autonomous System sub-TLV.
        asSubTlv.writeUint16(4);              // Length.
        asSubTlv.writeUint32(originAsn);      // AS number.
        byte[] asBytes = asSubTlv.toByteArray();

        ByteWriter localNodeDesc = new ByteWriter();
        localNodeDesc.writeUint16(256);       // Local Node Descriptors TLV.
        localNodeDesc.writeUint16(asBytes.length);
        localNodeDesc.writeBytes(asBytes);
        byte[] descBytes = localNodeDesc.toByteArray();

        ByteWriter nodeBody = new ByteWriter();
        nodeBody.writeUint8(3);               // Protocol-ID: OSPFv2 (RFC 7752 §3.2).
        nodeBody.writeUint64(0L);             // Identifier (routing universe).
        nodeBody.writeBytes(descBytes);
        byte[] body = nodeBody.toByteArray();

        ByteWriter nlri = new ByteWriter();
        nlri.writeUint16(1);                  // Node NLRI type.
        nlri.writeUint16(body.length);        // Total NLRI Length.
        nlri.writeBytes(body);

        return new MpReachNlri(AddressFamily.AFI_BGP_LS, AddressFamily.SAFI_BGP_LS,
                v4(NEXT_HOP_V4).getAddress(), nlri.toByteArray());
    }

    // ------------------------------------------------------------------
    // Attribute builders
    // ------------------------------------------------------------------

    /**
     * Builds a realistic, mostly-AS_SEQUENCE AS_PATH ending in {@code originAsn}, with an
     * occasional AS_SET or AS_CONFED_SEQUENCE segment (RFC 4271 §5.1.2, RFC 5065).
     *
     * <p>The path always ends with an AS_SEQUENCE segment so that
     * {@link AsPath#originAsn()} resolves to {@code originAsn}.
     *
     * @param rng       the deterministic RNG
     * @param originAsn the origin ASN at the tail of the path
     * @return the assembled AS_PATH attribute
     */
    private AsPath asPath(SplittableRandom rng, long originAsn) {
        List<AsPathSegment> segments = new ArrayList<>();

        if (rng.nextDouble() < P_AS_CONFED) {
            // Leading confederation sequence (RFC 5065): member-AS hops inside a confed.
            segments.add(new AsPathSegment(AsPathSegmentType.AS_CONFED_SEQUENCE,
                    new long[] {doc16Asn(rng), doc16Asn(rng)}));
        }

        // Main transit AS_SEQUENCE: upstream + 1..3 transit ASNs.
        List<Long> seq = new ArrayList<>();
        seq.add(UPSTREAM_ASN);
        int transitHops = 1 + rng.nextInt(3);
        for (int i = 0; i < transitHops; i++) {
            seq.add(TRANSIT_ASN + rng.nextInt(50));
        }

        if (rng.nextDouble() < P_AS_SET) {
            // An AS_SET segment representing an aggregation of two origin ASes; the trailing
            // AS_SEQUENCE below still carries the true origin so originAsn() stays correct.
            segments.add(new AsPathSegment(AsPathSegmentType.AS_SEQUENCE, toArray(seq)));
            segments.add(new AsPathSegment(AsPathSegmentType.AS_SET,
                    new long[] {originAsn, ASN_DOC_BASE + rng.nextInt(1000)}));
            segments.add(new AsPathSegment(AsPathSegmentType.AS_SEQUENCE,
                    new long[] {originAsn}));
        } else {
            seq.add(originAsn);
            segments.add(new AsPathSegment(AsPathSegmentType.AS_SEQUENCE, toArray(seq)));
        }
        return new AsPath(List.copyOf(segments));
    }

    /**
     * Appends 0–{@value #MAX_STD_COMMUNITIES} standard communities (RFC 1997), always
     * including NO_EXPORT so a well-known value is present.
     *
     * @param rng        the deterministic RNG
     * @param originAsn  the origin ASN, forming the AS half of each community
     * @param attributes the attribute list to append to
     */
    private void addStandardCommunities(SplittableRandom rng, long originAsn,
                                        List<PathAttribute> attributes) {
        int count = rng.nextInt(MAX_STD_COMMUNITIES + 1);
        if (count == 0) {
            return;
        }
        int[] values = new int[count];
        for (int i = 0; i < count - 1; i++) {
            values[i] = community(originAsn, 1 + rng.nextInt(0xFFFF));
        }
        values[count - 1] = COMMUNITY_NO_EXPORT;
        attributes.add(new Communities(values));
    }

    /**
     * Appends 0–{@value #MAX_LARGE_COMMUNITIES} large communities (RFC 8092), each with the
     * origin AS as the Global Administrator field.
     *
     * @param rng        the deterministic RNG
     * @param originAsn  the origin ASN (Global Administrator field)
     * @param attributes the attribute list to append to
     */
    private void addLargeCommunities(SplittableRandom rng, long originAsn,
                                     List<PathAttribute> attributes) {
        int count = rng.nextInt(MAX_LARGE_COMMUNITIES + 1);
        if (count == 0) {
            return;
        }
        List<LargeCommunity> communities = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            communities.add(new LargeCommunity(originAsn,
                    rng.nextLong(MAX_UINT32 + 1), rng.nextLong(MAX_UINT32 + 1)));
        }
        attributes.add(new LargeCommunities(communities));
    }

    /**
     * Appends 0–{@value #MAX_EXT_COMMUNITIES} extended communities (RFC 4360); the first,
     * when present, is a Route Target so the de facto common case appears.
     *
     * @param rng         the deterministic RNG
     * @param originAsn   the origin ASN, forming the Global Administrator of each community
     * @param routeTarget whether to force at least one Route Target community
     * @param attributes  the attribute list to append to
     */
    private void addExtendedCommunities(SplittableRandom rng, long originAsn, boolean routeTarget,
                                        List<PathAttribute> attributes) {
        int count = rng.nextInt(MAX_EXT_COMMUNITIES + 1);
        if (count == 0 && !routeTarget) {
            return;
        }
        count = Math.max(count, routeTarget ? 1 : 0);
        List<ExtendedCommunity> communities = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            int subType = (i == 0 && routeTarget) ? EXT_SUBTYPE_ROUTE_TARGET
                    : (rng.nextBoolean() ? EXT_SUBTYPE_ROUTE_TARGET : EXT_SUBTYPE_ROUTE_ORIGIN);
            communities.add(twoOctetAsExtCommunity(subType, originAsn, rng.nextInt(0xFFFF)));
        }
        attributes.add(new ExtendedCommunities(communities));
    }

    /**
     * Builds an {@link ExtendedCommunities} attribute carrying a single Route Target
     * (RFC 4360 §4 / RFC 4364 §4.3.1), as required on an L3VPN route, plus an occasional
     * IPv4-address Route Target.
     *
     * @param rng       the deterministic RNG
     * @param originAsn the origin ASN, forming the Global Administrator of the RT
     * @return the EXTENDED COMMUNITIES attribute
     */
    private ExtendedCommunities routeTargetExtCommunities(SplittableRandom rng, long originAsn) {
        List<ExtendedCommunity> communities = new ArrayList<>(2);
        // Two-octet-AS Route Target: type 0x00, sub-type 0x02 (RFC 4360 §3.1).
        communities.add(twoOctetAsExtCommunity(EXT_SUBTYPE_ROUTE_TARGET, originAsn,
                1 + rng.nextInt(0xFFFF)));
        if (rng.nextBoolean()) {
            // IPv4-address Route Target: type 0x01, sub-type 0x02 (RFC 4360 §3.2).
            byte[] value = new byte[8];
            value[0] = (byte) EXT_TYPE_IPV4;
            value[1] = (byte) EXT_SUBTYPE_ROUTE_TARGET;
            byte[] addr = v4FromInt(CLUSTER_ID_NET | (1 + rng.nextInt(254))).getAddress();
            System.arraycopy(addr, 0, value, 2, 4);
            int localNumber = 1 + rng.nextInt(0xFFFF);
            value[6] = (byte) (localNumber >>> 8);
            value[7] = (byte) localNumber;
            communities.add(new ExtendedCommunity(value));
        }
        return new ExtendedCommunities(communities);
    }

    /**
     * Builds a two-octet-AS transitive extended community (RFC 4360 §3.1): type 0x00, the
     * supplied sub-type, a 2-octet AS Global Administrator and a 4-octet Local
     * Administrator.
     *
     * @param subType   the sub-type octet (e.g. Route Target or Route Origin)
     * @param originAsn the AS whose low 16 bits form the Global Administrator
     * @param local     the 4-octet Local Administrator value (low 16 bits used)
     * @return the assembled extended community
     */
    private ExtendedCommunity twoOctetAsExtCommunity(int subType, long originAsn, int local) {
        int as16 = (int) (originAsn & 0xFFFF);
        byte[] value = new byte[8];
        value[0] = (byte) EXT_TYPE_2OCTET_AS;
        value[1] = (byte) subType;
        value[2] = (byte) (as16 >>> 8);
        value[3] = (byte) as16;
        value[4] = 0;
        value[5] = 0;
        value[6] = (byte) (local >>> 8);
        value[7] = (byte) local;
        return new ExtendedCommunity(value);
    }

    /**
     * Builds a CLUSTER_LIST of 1–2 CLUSTER_IDs (RFC 4456).
     *
     * @param rng the deterministic RNG
     * @return the CLUSTER_LIST attribute
     */
    private ClusterList clusterList(SplittableRandom rng) {
        int count = 1 + rng.nextInt(2);
        List<Inet4Address> ids = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            ids.add(v4FromInt(CLUSTER_ID_NET | (1 + rng.nextInt(254))));
        }
        return new ClusterList(ids);
    }

    // ------------------------------------------------------------------
    // Value helpers
    // ------------------------------------------------------------------

    /**
     * Builds a type-0 (2-byte-AS:4-byte-number) Route Distinguisher wire encoding from the
     * origin AS (RFC 4364 §4.2): 2-octet RD type, 2-octet AS, 4-octet assigned number.
     *
     * @param originAsn the AS whose low 16 bits form the RD AS field
     * @return the 8-octet Route Distinguisher
     */
    private static byte[] routeDistinguisher(long originAsn) {
        int as16 = (int) (originAsn & 0xFFFF);
        ByteWriter w = new ByteWriter(8);
        w.writeUint16(0);          // RD type 0.
        w.writeUint16(as16);       // 2-octet AS.
        w.writeUint32(1L);         // 4-octet assigned number.
        return w.toByteArray();
    }

    /**
     * Picks an ORIGIN type, weighted toward IGP as on a real feed (RFC 4271 §5.1.1).
     *
     * @param rng the deterministic RNG
     * @return the chosen ORIGIN type
     */
    private static OriginType originType(SplittableRandom rng) {
        double r = rng.nextDouble();
        if (r < 0.80) {
            return OriginType.IGP;
        }
        return r < 0.95 ? OriginType.INCOMPLETE : OriginType.EGP;
    }

    /**
     * Picks a LOCAL_PREF, biased toward the common default of 100 (RFC 4271 §5.1.5).
     *
     * @param rng the deterministic RNG
     * @return the chosen LOCAL_PREF value
     */
    private static long localPref(SplittableRandom rng) {
        return switch (rng.nextInt(4)) {
            case 0 -> 50L;
            case 1 -> 200L;
            case 2 -> 300L;
            default -> 100L;
        };
    }

    /**
     * Picks an aggregating AS number from the 32-bit documentation range (RFC 5398).
     *
     * @param rng the deterministic RNG
     * @return the aggregator ASN
     */
    private static long aggregatorAsn(SplittableRandom rng) {
        return ASN_DOC_BASE + rng.nextInt(1000);
    }

    /**
     * Picks a 16-bit documentation AS number from the RFC 5398 range [64496, 64511].
     *
     * @param rng the deterministic RNG
     * @return the 16-bit documentation ASN
     */
    private static long doc16Asn(SplittableRandom rng) {
        return ASN_DOC_16_BASE + rng.nextInt((int) (ASN_DOC_16_TOP - ASN_DOC_16_BASE + 1));
    }

    /**
     * Packs an RFC 1997 community from the low 16 bits of an AS and a value half.
     *
     * @param originAsn the origin ASN (its low 16 bits form the community AS half)
     * @param value     the community value half
     * @return the packed 32-bit community
     */
    private static int community(long originAsn, int value) {
        return (int) (((originAsn & 0xFFFFL) << 16) | (value & 0xFFFFL));
    }

    /**
     * Copies a list of {@code Long} into a primitive {@code long[]}.
     *
     * @param values the values to copy
     * @return a fresh primitive array
     */
    private static long[] toArray(List<Long> values) {
        long[] out = new long[values.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = values.get(i);
        }
        return out;
    }

    /**
     * Derives a {@link SplittableRandom} from the {@code (routerIndex, peerIndex,
     * prefixIndex)} triple so each announcement's attributes are reproducible.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index
     * @param prefixIndex the prefix ordinal
     * @return a deterministically-seeded RNG
     */
    private static SplittableRandom seededRandom(int routerIndex, int peerIndex, int prefixIndex) {
        long seed = 0x9E3779B97F4A7C15L; // golden-ratio odd constant (Fibonacci hashing).
        seed = (seed ^ routerIndex) * 0xFF51AFD7ED558CCDL;
        seed = (seed ^ peerIndex) * 0xC4CEB9FE1A85EC53L;
        seed = (seed ^ prefixIndex) * 0x9E3779B97F4A7C15L;
        return new SplittableRandom(seed);
    }

    private static Inet4Address v4(String s) {
        try {
            return (Inet4Address) InetAddress.getByName(s);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Invalid literal IPv4 address: " + s, e);
        }
    }

    private static Inet4Address v4FromInt(int value) {
        byte[] bytes = {
                (byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value};
        try {
            return (Inet4Address) InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Cannot build IPv4 address from " + value, e);
        }
    }

    /**
     * The product of building one announcement: the path attributes in wire order and the
     * IPv4-unicast NLRI to advertise (empty for a multiprotocol route, whose reachability
     * is carried inside its {@link MpReachNlri} attribute instead).
     *
     * @param attributes the path attributes in wire order
     * @param nlri        the IPv4-unicast advertised routes (possibly empty)
     */
    record Announcement(List<PathAttribute> attributes, List<IpPrefix> nlri) {

        /**
         * Validates and defensively copies the lists.
         */
        Announcement {
            attributes = List.copyOf(attributes);
            nlri = List.copyOf(nlri);
        }
    }
}
