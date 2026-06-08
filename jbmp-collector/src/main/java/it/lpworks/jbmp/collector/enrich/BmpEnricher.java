package it.lpworks.jbmp.collector.enrich;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

import org.springframework.stereotype.Component;

import it.lpworks.jbmp.identity.UuidFactory;
import it.lpworks.jbmp.protocol.bgp.AddPathNlri;
import it.lpworks.jbmp.protocol.bgp.Aggregator;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AtomicAggregate;
import it.lpworks.jbmp.protocol.bgp.BgpUpdate;
import it.lpworks.jbmp.protocol.bgp.ClusterList;
import it.lpworks.jbmp.protocol.bgp.Communities;
import it.lpworks.jbmp.protocol.bgp.EvpnRoute;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunities;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunity;
import it.lpworks.jbmp.protocol.bgp.FlowSpecRule;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bgp.LargeCommunities;
import it.lpworks.jbmp.protocol.bgp.LargeCommunity;
import it.lpworks.jbmp.protocol.bgp.LinkStateNlri;
import it.lpworks.jbmp.protocol.bgp.LocalPref;
import it.lpworks.jbmp.protocol.bgp.MpReachNlri;
import it.lpworks.jbmp.protocol.bgp.MpUnreachNlri;
import it.lpworks.jbmp.protocol.bgp.MultiExitDisc;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Nlri;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginatorId;
import it.lpworks.jbmp.protocol.bgp.RawNlri;
import it.lpworks.jbmp.protocol.bgp.RouteDistinguisher;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.bgp.SrPolicyNlri;
import it.lpworks.jbmp.protocol.bgp.UnknownAttribute;
import it.lpworks.jbmp.protocol.bgp.VpnPrefix;
import it.lpworks.jbmp.protocol.bmp.PeerDownNotification;
import it.lpworks.jbmp.protocol.bmp.PeerDownReason;
import it.lpworks.jbmp.protocol.bmp.PeerType;
import it.lpworks.jbmp.protocol.bmp.PeerUpNotification;
import it.lpworks.jbmp.protocol.bmp.PerPeerHeader;
import it.lpworks.jbmp.protocol.bmp.RouteMirroring;
import it.lpworks.jbmp.protocol.bmp.RouteMonitoring;
import it.lpworks.jbmp.protocol.bmp.StatisticsReport;
import it.lpworks.jbmp.protocol.bmp.stat.StatCounter;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;
import it.lpworks.jbmp.protocol.parser.bgp.NlriDecoder;
import it.lpworks.jbmp.wire.AsPathSegmentInfo;
import it.lpworks.jbmp.wire.MessageHeader;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.PeerEventType;
import it.lpworks.jbmp.wire.RouteAction;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;

/**
 * Converts parsed BMP messages plus per-connection {@link EnrichmentContext} into the
 * enriched wire DTOs of {@link it.lpworks.jbmp.wire}.
 *
 * <p>The enricher is stateless and therefore safe to share across all router-session virtual
 * threads. It resolves the deterministic router and peer identities
 * ({@link UuidFactory}), explodes each BGP UPDATE into one
 * {@link RouteMonitorMessage} per prefix, decodes the multiprotocol NLRI carried by
 * {@link MpReachNlri}/{@link MpUnreachNlri} (RFC 4760) via {@link NlriDecoder}, and decodes
 * the BGP NOTIFICATION embedded in a Peer Down (RFC 7854 §4.9, RFC 4271 §4.5).
 *
 * <h2>Route-monitor field mapping</h2>
 * <p>For each advertised/withdrawn NLRI a single {@code RouteMonitorMessage} is emitted with:
 * <ul>
 *   <li><b>action</b> ANNOUNCE for reachability, WITHDRAW for unreachability;</li>
 *   <li><b>prefix/prefixLength</b> from {@link IpPrefix} (the inner prefix for a
 *       {@link VpnPrefix}); the opaque families (EVPN, Flow Spec, SR Policy, BGP-LS and any
 *       {@link RawNlri}) leave the prefix empty and populate the matching blob field with
 *       their raw bytes;</li>
 *   <li><b>ipv4</b> from the address family;</li>
 *   <li><b>nextHop</b> from the {@link NextHop} attribute, or the MP_REACH next-hop bytes for
 *       multiprotocol announcements;</li>
 *   <li><b>origin AS, AS path and segments</b> from {@link AsPath}; <b>MED, LOCAL_PREF,
 *       ORIGIN, ATOMIC_AGGREGATE, AGGREGATOR</b> from their attributes;</li>
 *   <li><b>communities/largeCommunities/extendedCommunities</b> from their attributes, with
 *       <b>routeTargets</b> being the hex text of the route-target extended communities
 *       (RFC 4360 sub-type {@code 0x02});</li>
 *   <li><b>originatorId/clusterList</b> mapped through {@link UuidFactory#router(byte[])} on
 *       the respective 4-byte BGP identifiers (RFC 4456);</li>
 *   <li><b>prePolicy</b> = {@code !L-flag}; <b>locRib</b> when the peer type is Loc-RIB
 *       (RFC 9069); <b>endOfRib</b> from {@link BgpUpdate#isEndOfRib()};</li>
 *   <li><b>peerRd/vprnId/mplsLabels</b> for VPN routes (RFC 4364), where {@code vprnId} is the
 *       low 32 bits of the RD value (see {@link #vprnIdFromRd(RouteDistinguisher)});</li>
 *   <li><b>timestampNanos</b> from the Per-Peer Header timestamp and <b>receivedAtNanos</b>
 *       from the context.</li>
 * </ul>
 *
 * <p>Initiation and Termination messages produce no DTO and are handled (logged/counted) by
 * the caller.
 */
@Component
public class BmpEnricher {

    /** Nanoseconds in one second, for Per-Peer Header timestamp conversion. */
    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    /** Length, in octets, of the fixed BGP message header (RFC 4271 §4.1). */
    private static final int BGP_HEADER_LEN = 19;

    /** Mask for the low 32 bits, used to derive the VPRN id from a Route Distinguisher. */
    private static final long LOW_32_MASK = 0xFFFFFFFFL;

    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final long[] EMPTY_LONGS = new long[0];

    /** BGP-LS path attribute type code (RFC 7752 §3.3), preserved verbatim as the LS attribute. */
    private static final int BGP_LS_ATTR_TYPE = 29;

    /**
     * Enriches a Route Monitoring message into one {@link RouteMonitorMessage} per prefix.
     *
     * <p>IPv4-unicast reachability and withdrawal come from the UPDATE's {@code nlri} and
     * {@code withdrawnRoutes} lists; multiprotocol reachability/withdrawal is decoded from the
     * MP_REACH/MP_UNREACH attributes. An End-of-RIB UPDATE (RFC 4724) carries no prefixes and
     * yields a single marker message.
     *
     * @param message the parsed Route Monitoring message (never {@code null})
     * @param context the per-connection context (never {@code null})
     * @return an immutable list of per-prefix route-monitor messages (possibly empty)
     */
    public List<RouteMonitorMessage> enrichRouteMonitoring(RouteMonitoring message,
                                                           EnrichmentContext context) {
        PerPeerHeader peer = message.peerHeader();
        BgpUpdate update = message.update();

        Ids ids = ids(peer, context);
        MessageHeader header = ids.header();
        String peerRd = ids.peerRd();

        boolean prePolicy = !peer.flags().postPolicy();
        boolean locRib = peer.peerType() == PeerType.LOC_RIB;

        // Shared attribute view computed once per UPDATE and reused for every prefix.
        Attributes attrs = extractAttributes(update);

        List<RouteMonitorMessage> out = new ArrayList<>();

        if (update.isEndOfRib()) {
            out.add(endOfRibMessage(header, prePolicy, locRib, peerRd, update));
            return List.copyOf(out);
        }

        // --- IPv4-unicast announcements and withdrawals (RFC 4271 §4.3). ---
        for (IpPrefix prefix : update.nlri()) {
            out.add(routeFromIpPrefix(header, RouteAction.ANNOUNCE, prefix, attrs,
                    attrs.nextHop, prePolicy, locRib, peerRd));
        }
        for (IpPrefix prefix : update.withdrawnRoutes()) {
            out.add(routeFromIpPrefix(header, RouteAction.WITHDRAW, prefix, attrs,
                    EMPTY_BYTES, prePolicy, locRib, peerRd));
        }

        // --- Multiprotocol reachability (RFC 4760 MP_REACH_NLRI). ---
        if (attrs.mpReach != null) {
            byte[] mpNextHop = attrs.mpReach.nextHop();
            for (Nlri nlri : NlriDecoder.decode(attrs.mpReach.afi(), attrs.mpReach.safi(),
                    attrs.mpReach.nlri(), false)) {
                out.add(routeFromNlri(header, RouteAction.ANNOUNCE, nlri, attrs, mpNextHop,
                        prePolicy, locRib, peerRd));
            }
        }

        // --- Multiprotocol withdrawal (RFC 4760 MP_UNREACH_NLRI); empty => End-of-RIB. ---
        if (attrs.mpUnreach != null && attrs.mpUnreach.withdrawnNlri().length > 0) {
            for (Nlri nlri : NlriDecoder.decode(attrs.mpUnreach.afi(), attrs.mpUnreach.safi(),
                    attrs.mpUnreach.withdrawnNlri(), false)) {
                out.add(routeFromNlri(header, RouteAction.WITHDRAW, nlri, attrs, EMPTY_BYTES,
                        prePolicy, locRib, peerRd));
            }
        }

        return List.copyOf(out);
    }

    /**
     * Enriches a Peer Up Notification into an {@code UP} {@link PeerEventMessage}.
     *
     * @param message the parsed Peer Up Notification (never {@code null})
     * @param context the per-connection context (never {@code null})
     * @return the enriched peer event
     */
    public PeerEventMessage enrichPeerUp(PeerUpNotification message, EnrichmentContext context) {
        PerPeerHeader peer = message.peerHeader();
        Ids ids = ids(peer, context);

        byte[] remoteIp = peer.address().getAddress();
        byte[] localIp = message.localAddress().getAddress();
        String infoData = joinInformationTlvs(message.informationTlvs());

        // The Per-Peer Header carries only the remote peer's ASN/BGP-Id; the local ASN and
        // local BGP-Id live inside the sent OPEN, which is preserved raw but not decoded here,
        // so they are reported as absent (0 / empty).
        return new PeerEventMessage(
                ids.header(),
                PeerEventType.UP,
                remoteIp,
                peer.peerAsn(),
                peer.bgpId().getAddress(),
                localIp,
                0,
                EMPTY_BYTES,
                message.remotePort(),
                message.localPort(),
                ids.peerRd(),
                !peer.flags().postPolicy(),
                !peer.flags().ipv6(),
                peer.peerType() == PeerType.LOC_RIB,
                0,
                0,
                0,
                "",
                message.sentOpenMessage(),
                message.receivedOpenMessage(),
                infoData);
    }

    /**
     * Enriches a Peer Down Notification into a {@code DOWN} {@link PeerEventMessage},
     * decoding the embedded BGP NOTIFICATION when the reason carries one.
     *
     * <p>Reasons 1 (local NOTIFICATION) and 3 (remote NOTIFICATION) carry a complete BGP
     * NOTIFICATION in {@code data}: after the 19-byte BGP header come the 1-byte Error code,
     * the 1-byte Error subcode and the variable Data field (RFC 4271 §4.5). The Data field is
     * rendered as UTF-8 text, falling back to a hex rendering when it is not valid UTF-8.
     *
     * @param message the parsed Peer Down Notification (never {@code null})
     * @param context the per-connection context (never {@code null})
     * @return the enriched peer event
     */
    public PeerEventMessage enrichPeerDown(PeerDownNotification message,
                                           EnrichmentContext context) {
        PerPeerHeader peer = message.peerHeader();
        Ids ids = ids(peer, context);

        int bgpErrorCode = 0;
        int bgpErrorSubcode = 0;
        String errorText = "";

        if (carriesNotification(message.reason())) {
            byte[] data = message.data();
            // NOTIFICATION layout: 19-byte BGP header, then code(1), subcode(1), data(*).
            if (data.length >= BGP_HEADER_LEN + 2) {
                bgpErrorCode = data[BGP_HEADER_LEN] & 0xFF;
                bgpErrorSubcode = data[BGP_HEADER_LEN + 1] & 0xFF;
                errorText = decodeNotificationData(data, BGP_HEADER_LEN + 2);
            }
        }

        // Peer Down has no local address/port fields; the local ASN is not available without
        // decoding the (no longer present) OPEN, so it is reported absent.
        return new PeerEventMessage(
                ids.header(),
                PeerEventType.DOWN,
                peer.address().getAddress(),
                peer.peerAsn(),
                peer.bgpId().getAddress(),
                EMPTY_BYTES,
                0,
                EMPTY_BYTES,
                0,
                0,
                ids.peerRd(),
                !peer.flags().postPolicy(),
                !peer.flags().ipv6(),
                peer.peerType() == PeerType.LOC_RIB,
                message.reasonCode(),
                bgpErrorCode,
                bgpErrorSubcode,
                errorText,
                EMPTY_BYTES,
                EMPTY_BYTES,
                "");
    }

    /**
     * Enriches a Statistics Report into a {@link StatsReportMessage}, collecting each
     * counter's {@code (statType, value)} pair into the report's counter map.
     *
     * @param message the parsed Statistics Report (never {@code null})
     * @param context the per-connection context (never {@code null})
     * @return the enriched stats report
     */
    public StatsReportMessage enrichStatisticsReport(StatisticsReport message,
                                                     EnrichmentContext context) {
        PerPeerHeader peer = message.peerHeader();
        Ids ids = ids(peer, context);

        java.util.TreeMap<Integer, Long> counters = new java.util.TreeMap<>();
        for (StatCounter counter : message.counters()) {
            // A later duplicate type wins; the wire map is sorted and deterministic.
            counters.put(counter.statType(), counter.value());
        }
        return new StatsReportMessage(ids.header(), counters);
    }

    /**
     * Enriches a Route Mirroring message into a {@link RouteMirrorMessage}, carrying the
     * mirrored BGP PDU bytes and any information code verbatim.
     *
     * @param message the parsed Route Mirroring message (never {@code null})
     * @param context the per-connection context (never {@code null})
     * @return the enriched route-mirror event
     */
    public RouteMirrorMessage enrichRouteMirroring(RouteMirroring message,
                                                   EnrichmentContext context) {
        PerPeerHeader peer = message.peerHeader();
        Ids ids = ids(peer, context);
        return new RouteMirrorMessage(
                ids.header(), message.mirroredBgpMessage(), message.informationCode());
    }

    // ------------------------------------------------------------------
    // Route-monitor helpers
    // ------------------------------------------------------------------

    /**
     * Builds a route-monitor message from an IPv4/IPv6 unicast {@link IpPrefix}.
     */
    private RouteMonitorMessage routeFromIpPrefix(MessageHeader header, RouteAction action,
                                                  IpPrefix prefix, Attributes attrs,
                                                  byte[] nextHop, boolean prePolicy,
                                                  boolean locRib, String peerRd) {
        return builder(header, action, prePolicy, locRib, peerRd, attrs)
                .ipv4(isIpv4(prefix.address()))
                .prefix(prefix.address().getAddress(), prefix.prefixLength())
                .nextHop(nextHop)
                .build();
    }

    /**
     * Builds a route-monitor message from a decoded multiprotocol {@link Nlri}, routing each
     * concrete NLRI kind to the correct typed or opaque field.
     */
    private RouteMonitorMessage routeFromNlri(MessageHeader header, RouteAction action,
                                              Nlri nlri, Attributes attrs, byte[] nextHop,
                                              boolean prePolicy, boolean locRib, String peerRd) {
        // Unwrap an ADD-PATH (RFC 7911) envelope, preserving the path id.
        OptionalLong pathId = OptionalLong.empty();
        Nlri inner = nlri;
        if (nlri instanceof AddPathNlri addPath) {
            pathId = OptionalLong.of(addPath.pathId());
            inner = addPath.nlri();
        }

        RouteBuilder b = builder(header, action, prePolicy, locRib, peerRd, attrs)
                .nextHop(nextHop)
                .addPath(pathId);

        switch (inner) {
            case VpnPrefix vpn -> b
                    .ipv4(isIpv4(vpn.prefix().address()))
                    .prefix(vpn.prefix().address().getAddress(), vpn.prefix().prefixLength())
                    .peerRd(vpn.rd().asText())
                    .vprnId(vprnIdFromRd(vpn.rd()))
                    .mplsLabels(vpn.mplsLabels());
            case IpPrefix ip -> b
                    .ipv4(isIpv4(ip.address()))
                    .prefix(ip.address().getAddress(), ip.prefixLength());
            case EvpnRoute evpn -> b.evpn(evpnWithRouteType(evpn));
            case FlowSpecRule flow -> b.flowSpec(flow.raw());
            case SrPolicyNlri sr -> b.srPolicy(sr.raw());
            case LinkStateNlri ls -> b.linkState(ls.raw());
            case RawNlri raw -> b.rawNlri(raw.data());
            default -> {
                // {@link Nlri} is an open interface; the decoder only yields the kinds above,
                // but a future implementation would fall here with all blob fields left empty
                // rather than throwing, keeping enrichment total.
            }
        }
        return b.build();
    }

    /**
     * Builds the single End-of-RIB marker message (RFC 4724) for an UPDATE that carries no
     * reachability information.
     */
    private RouteMonitorMessage endOfRibMessage(MessageHeader header, boolean prePolicy,
                                                boolean locRib, String peerRd, BgpUpdate update) {
        // The address family of a multiprotocol End-of-RIB is given by its MP_UNREACH; an
        // IPv4-unicast End-of-RIB has no attributes and defaults to IPv4.
        boolean ipv4 = update.attribute(MpUnreachNlri.class)
                .map(u -> u.afi() == it.lpworks.jbmp.protocol.bgp.AddressFamily.AFI_IPV4)
                .orElse(true);
        return new RouteBuilder(header, RouteAction.WITHDRAW, prePolicy, locRib, peerRd)
                .ipv4(ipv4)
                .endOfRib(true)
                .build();
    }

    /**
     * Seeds a route builder with the per-UPDATE attribute view shared by every prefix.
     */
    private RouteBuilder builder(MessageHeader header, RouteAction action, boolean prePolicy,
                                 boolean locRib, String peerRd, Attributes attrs) {
        return new RouteBuilder(header, action, prePolicy, locRib, peerRd)
                .originAsn(attrs.originAsn)
                .asPath(attrs.asPath)
                .asPathSegments(attrs.asPathSegments)
                .med(attrs.med)
                .localPref(attrs.localPref)
                .origin(attrs.origin)
                .atomicAggregate(attrs.atomicAggregate)
                .aggregator(attrs.aggregatorAsn, attrs.aggregatorAddress)
                .communities(attrs.communities)
                .largeCommunities(attrs.largeCommunities)
                .extendedCommunities(attrs.extendedCommunities)
                .routeTargets(attrs.routeTargets)
                .originatorId(attrs.originatorId)
                .clusterList(attrs.clusterList)
                .linkState(attrs.lsAttr);
    }

    // ------------------------------------------------------------------
    // Attribute extraction (computed once per UPDATE)
    // ------------------------------------------------------------------

    /**
     * The decoded, reusable view of a BGP UPDATE's path attributes.
     */
    private static final class Attributes {
        OptionalLong originAsn = OptionalLong.empty();
        long[] asPath = EMPTY_LONGS;
        List<AsPathSegmentInfo> asPathSegments = List.of();
        byte[] nextHop = EMPTY_BYTES;
        OptionalLong med = OptionalLong.empty();
        OptionalLong localPref = OptionalLong.empty();
        int origin = -1;
        boolean atomicAggregate = false;
        OptionalLong aggregatorAsn = OptionalLong.empty();
        byte[] aggregatorAddress = EMPTY_BYTES;
        int[] communities = new int[0];
        List<LargeCommunity> largeCommunities = List.of();
        List<byte[]> extendedCommunities = List.of();
        List<String> routeTargets = List.of();
        Optional<UUID> originatorId = Optional.empty();
        List<UUID> clusterList = List.of();
        byte[] lsAttr = EMPTY_BYTES;
        MpReachNlri mpReach;
        MpUnreachNlri mpUnreach;
    }

    /**
     * Extracts every attribute the enricher maps from a BGP UPDATE into a single reusable
     * {@link Attributes} view, so per-prefix construction does no repeated attribute scanning.
     */
    private Attributes extractAttributes(BgpUpdate update) {
        Attributes a = new Attributes();
        update.attribute(AsPath.class).ifPresent(asPath -> {
            a.originAsn = asPath.originAsn();
            a.asPath = flattenAsPath(asPath);
            a.asPathSegments = segments(asPath);
        });
        update.attribute(NextHop.class)
                .ifPresent(nh -> a.nextHop = nh.address().getAddress());
        update.attribute(MultiExitDisc.class)
                .ifPresent(med -> a.med = OptionalLong.of(med.med()));
        update.attribute(LocalPref.class)
                .ifPresent(lp -> a.localPref = OptionalLong.of(lp.localPreference()));
        update.attribute(Origin.class)
                .ifPresent(o -> a.origin = o.value().code());
        a.atomicAggregate = update.attribute(AtomicAggregate.class).isPresent();
        update.attribute(Aggregator.class).ifPresent(agg -> {
            a.aggregatorAsn = OptionalLong.of(agg.asn());
            a.aggregatorAddress = agg.address().getAddress();
        });
        update.attribute(Communities.class)
                .ifPresent(c -> a.communities = c.values());
        update.attribute(LargeCommunities.class)
                .ifPresent(lc -> a.largeCommunities = lc.communities());
        update.attribute(ExtendedCommunities.class).ifPresent(ec -> {
            List<ExtendedCommunity> list = ec.communities();
            List<byte[]> values = new ArrayList<>(list.size());
            List<String> rts = new ArrayList<>();
            for (ExtendedCommunity community : list) {
                values.add(community.value());
                if (community.isRouteTarget()) {
                    rts.add(community.asText());
                }
            }
            a.extendedCommunities = values;
            a.routeTargets = rts;
        });
        update.attribute(OriginatorId.class)
                .ifPresent(oid -> a.originatorId =
                        Optional.of(UuidFactory.router(oid.id().getAddress())));
        update.attribute(ClusterList.class).ifPresent(cl -> {
            List<UUID> ids = new ArrayList<>(cl.clusterIds().size());
            for (var clusterId : cl.clusterIds()) {
                ids.add(UuidFactory.router(clusterId.getAddress()));
            }
            a.clusterList = ids;
        });
        // BGP-LS attribute (RFC 7752, type 29): not modelled as a typed attribute, so it arrives
        // as an UnknownAttribute. Preserve its raw value as the link-state attribute blob.
        for (PathAttribute attr : update.pathAttributes()) {
            if (attr instanceof UnknownAttribute unknown && unknown.typeCode() == BGP_LS_ATTR_TYPE) {
                a.lsAttr = unknown.value();
                break;
            }
        }
        a.mpReach = update.attribute(MpReachNlri.class).orElse(null);
        a.mpUnreach = update.attribute(MpUnreachNlri.class).orElse(null);
        return a;
    }

    /**
     * Prefixes the 1-octet EVPN Route Type to the route's type-specific field, so the consumer
     * can decode the route without the type having its own wire field. The decoder reads the
     * route type from byte 0 and the type-specific body from byte 1 onward.
     */
    private static byte[] evpnWithRouteType(EvpnRoute evpn) {
        byte[] raw = evpn.raw();
        byte[] out = new byte[raw.length + 1];
        out[0] = (byte) evpn.routeType();
        System.arraycopy(raw, 0, out, 1, raw.length);
        return out;
    }

    /**
     * Flattens an AS_PATH into an ordered ASN array, in wire order across all segments.
     */
    private static long[] flattenAsPath(AsPath asPath) {
        List<AsPathSegment> segments = asPath.segments();
        int total = 0;
        for (AsPathSegment seg : segments) {
            total += seg.asns().length;
        }
        if (total == 0) {
            return EMPTY_LONGS;
        }
        long[] out = new long[total];
        int idx = 0;
        for (AsPathSegment seg : segments) {
            long[] asns = seg.asns();
            System.arraycopy(asns, 0, out, idx, asns.length);
            idx += asns.length;
        }
        return out;
    }

    /**
     * Maps each AS_PATH segment to its wire {@link AsPathSegmentInfo}, preserving the segment
     * type code (RFC 4271 §5.1.2, RFC 5065).
     */
    private static List<AsPathSegmentInfo> segments(AsPath asPath) {
        List<AsPathSegment> segments = asPath.segments();
        List<AsPathSegmentInfo> out = new ArrayList<>(segments.size());
        for (AsPathSegment seg : segments) {
            out.add(new AsPathSegmentInfo(seg.type().code(), seg.asns()));
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Identity / header helpers
    // ------------------------------------------------------------------

    /** The deterministic identities plus the resolved header and RD for a peer/context. */
    private record Ids(MessageHeader header, String peerRd) {
    }

    /**
     * Resolves the router/peer identities and provenance header for a per-peer header and the
     * connection context.
     */
    private Ids ids(PerPeerHeader peer, EnrichmentContext context) {
        // The router key is the TCP source IP (see EnrichmentContext), hashed to a stable routerId.
        UUID routerId = UuidFactory.router(context.routerKey());
        String peerRd = peerRdText(peer);
        UUID peerId = UuidFactory.peer(routerId, peer.address().getAddress(),
                peer.peerAsn(), peerRd);
        MessageHeader header = new MessageHeader(
                timestampNanos(peer.timestamp()),
                context.receivedAtNanos().getAsLong(),
                context.collectorId(),
                routerId,
                peerId);
        return new Ids(header, peerRd);
    }

    /**
     * Returns the textual Route Distinguisher for an RD/Local-instance peer (RFC 7854 §4.2),
     * or the empty string for other peer types where the distinguisher is reserved zero.
     */
    private static String peerRdText(PerPeerHeader peer) {
        if (peer.peerType() == PeerType.RD_INSTANCE) {
            byte[] dist = peer.distinguisher();
            int type = ((dist[0] & 0xFF) << 8) | (dist[1] & 0xFF);
            byte[] value = java.util.Arrays.copyOfRange(dist, 2, 8);
            return new RouteDistinguisher(type, value).asText();
        }
        return "";
    }

    /**
     * Converts a Per-Peer Header {@link Instant} to nanoseconds since the Unix epoch.
     */
    private static long timestampNanos(Instant instant) {
        return instant.getEpochSecond() * NANOS_PER_SECOND + instant.getNano();
    }

    // ------------------------------------------------------------------
    // Peer-down NOTIFICATION helpers
    // ------------------------------------------------------------------

    /**
     * Reports whether a Peer Down reason carries an embedded BGP NOTIFICATION (RFC 7854 §4.9).
     */
    private static boolean carriesNotification(PeerDownReason reason) {
        return reason == PeerDownReason.LOCAL_NOTIFICATION
                || reason == PeerDownReason.REMOTE_NOTIFICATION;
    }

    /**
     * Decodes the NOTIFICATION Data field (RFC 4271 §4.5) as UTF-8 text, falling back to a
     * lowercase hex rendering when the bytes are not valid UTF-8 or empty.
     */
    private static String decodeNotificationData(byte[] data, int from) {
        if (from >= data.length) {
            return "";
        }
        byte[] slice = java.util.Arrays.copyOfRange(data, from, data.length);
        if (isValidUtf8(slice)) {
            return new String(slice, StandardCharsets.UTF_8);
        }
        return HexFormat.of().formatHex(slice);
    }

    /**
     * Reports whether a byte array is valid UTF-8 by round-tripping it through the decoder.
     */
    private static boolean isValidUtf8(byte[] bytes) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                    .decode(java.nio.ByteBuffer.wrap(bytes));
            return true;
        } catch (java.nio.charset.CharacterCodingException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Information TLV / VPRN helpers
    // ------------------------------------------------------------------

    /**
     * Joins the UTF-8 text of every Information TLV (RFC 7854 §4.4) with newlines.
     */
    private static String joinInformationTlvs(List<InformationTlv> tlvs) {
        if (tlvs.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (InformationTlv tlv : tlvs) {
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(tlv.asString());
        }
        return sb.toString();
    }

    /**
     * Derives an implementation-assigned VPRN/VRF identifier from a Route Distinguisher
     * (RFC 4364 §4.2) as the low 32 bits of its 6-octet value.
     *
     * <p>The RD value is a 6-octet field whose interpretation depends on the RD type; the
     * trailing four octets are the assigned number for type 0 and type 2 RDs and the 2-octet
     * number plus the low 16 bits of the IPv4 address for type 1. Taking the low 32 bits gives
     * a stable, type-agnostic numeric handle suitable for grouping routes by VRF; it is not a
     * globally unique key and is intended only as a local correlation id.
     *
     * @param rd the Route Distinguisher
     * @return the low 32 bits of the RD value as an unsigned {@code long}
     */
    private static long vprnIdFromRd(RouteDistinguisher rd) {
        byte[] v = rd.value(); // 6 octets
        long low32 = ((long) (v[2] & 0xFF) << 24)
                | ((long) (v[3] & 0xFF) << 16)
                | ((long) (v[4] & 0xFF) << 8)
                | (v[5] & 0xFF);
        return low32 & LOW_32_MASK;
    }

    /**
     * Reports whether an address is IPv4.
     */
    private static boolean isIpv4(InetAddress address) {
        return address instanceof java.net.Inet4Address;
    }

    // ------------------------------------------------------------------
    // Route-monitor builder
    // ------------------------------------------------------------------

    /**
     * A small mutable builder that assembles a {@link RouteMonitorMessage}, defaulting every
     * optional field to its absent representation so a caller need set only what applies.
     */
    private static final class RouteBuilder {
        private final MessageHeader header;
        private final RouteAction action;
        private final boolean prePolicy;
        private final boolean locRib;

        // Seeded from the per-peer RD; a VPN NLRI supersedes it via peerRd(String).
        private String peerRd;

        private boolean ipv4;
        private boolean endOfRib;
        private boolean addPath;
        private byte[] prefix = EMPTY_BYTES;
        private int prefixLength;
        private OptionalLong pathId = OptionalLong.empty();
        private OptionalLong originAsn = OptionalLong.empty();
        private long[] asPath = EMPTY_LONGS;
        private List<AsPathSegmentInfo> asPathSegments = List.of();
        private byte[] nextHop = EMPTY_BYTES;
        private OptionalLong med = OptionalLong.empty();
        private OptionalLong localPref = OptionalLong.empty();
        private int origin = -1;
        private boolean atomicAggregate;
        private OptionalLong aggregatorAsn = OptionalLong.empty();
        private byte[] aggregatorAddress = EMPTY_BYTES;
        private int[] communities = new int[0];
        private List<LargeCommunity> largeCommunities = List.of();
        private List<byte[]> extendedCommunities = List.of();
        private Optional<UUID> originatorId = Optional.empty();
        private List<UUID> clusterList = List.of();
        private long vprnId;
        private List<String> routeTargets = List.of();
        private long[] mplsLabels = EMPTY_LONGS;
        private byte[] evpn = EMPTY_BYTES;
        private byte[] flowSpec = EMPTY_BYTES;
        private byte[] srPolicy = EMPTY_BYTES;
        private byte[] linkState = EMPTY_BYTES;
        private byte[] rawNlri = EMPTY_BYTES;

        RouteBuilder(MessageHeader header, RouteAction action, boolean prePolicy,
                     boolean locRib, String peerRd) {
            this.header = header;
            this.action = action;
            this.prePolicy = prePolicy;
            this.locRib = locRib;
            this.peerRd = peerRd;
        }

        RouteBuilder ipv4(boolean v) {
            this.ipv4 = v;
            return this;
        }

        RouteBuilder endOfRib(boolean v) {
            this.endOfRib = v;
            return this;
        }

        RouteBuilder addPath(OptionalLong id) {
            this.pathId = id;
            this.addPath = id.isPresent();
            return this;
        }

        RouteBuilder prefix(byte[] bytes, int length) {
            this.prefix = bytes;
            this.prefixLength = length;
            return this;
        }

        RouteBuilder originAsn(OptionalLong v) {
            this.originAsn = v;
            return this;
        }

        RouteBuilder asPath(long[] v) {
            this.asPath = v;
            return this;
        }

        RouteBuilder asPathSegments(List<AsPathSegmentInfo> v) {
            this.asPathSegments = v;
            return this;
        }

        RouteBuilder nextHop(byte[] v) {
            this.nextHop = v;
            return this;
        }

        RouteBuilder med(OptionalLong v) {
            this.med = v;
            return this;
        }

        RouteBuilder localPref(OptionalLong v) {
            this.localPref = v;
            return this;
        }

        RouteBuilder origin(int v) {
            this.origin = v;
            return this;
        }

        RouteBuilder atomicAggregate(boolean v) {
            this.atomicAggregate = v;
            return this;
        }

        RouteBuilder aggregator(OptionalLong asn, byte[] address) {
            this.aggregatorAsn = asn;
            this.aggregatorAddress = address;
            return this;
        }

        RouteBuilder communities(int[] v) {
            this.communities = v;
            return this;
        }

        RouteBuilder largeCommunities(List<LargeCommunity> v) {
            this.largeCommunities = v;
            return this;
        }

        RouteBuilder extendedCommunities(List<byte[]> v) {
            this.extendedCommunities = v;
            return this;
        }

        RouteBuilder originatorId(Optional<UUID> v) {
            this.originatorId = v;
            return this;
        }

        RouteBuilder clusterList(List<UUID> v) {
            this.clusterList = v;
            return this;
        }

        RouteBuilder vprnId(long v) {
            this.vprnId = v;
            return this;
        }

        RouteBuilder routeTargets(List<String> v) {
            this.routeTargets = v;
            return this;
        }

        RouteBuilder peerRd(String overrideRd) {
            // VPN routes carry the RD from the NLRI itself, which supersedes the per-peer RD.
            if (overrideRd != null) {
                this.peerRd = overrideRd;
            }
            return this;
        }

        RouteBuilder mplsLabels(long[] v) {
            this.mplsLabels = v;
            return this;
        }

        RouteBuilder evpn(byte[] v) {
            this.evpn = v;
            return this;
        }

        RouteBuilder flowSpec(byte[] v) {
            this.flowSpec = v;
            return this;
        }

        RouteBuilder srPolicy(byte[] v) {
            this.srPolicy = v;
            return this;
        }

        RouteBuilder linkState(byte[] v) {
            this.linkState = v;
            return this;
        }

        RouteBuilder rawNlri(byte[] v) {
            this.rawNlri = v;
            return this;
        }

        RouteMonitorMessage build() {
            return new RouteMonitorMessage(
                    header, action, prePolicy, locRib, ipv4, endOfRib, addPath,
                    prefix, prefixLength, pathId, originAsn, asPath, asPathSegments, nextHop,
                    med, localPref, origin, atomicAggregate, aggregatorAsn, aggregatorAddress,
                    communities, largeCommunities, extendedCommunities, originatorId,
                    clusterList, peerRd, vprnId, routeTargets, mplsLabels,
                    evpn, flowSpec, srPolicy, linkState, rawNlri);
        }
    }
}
