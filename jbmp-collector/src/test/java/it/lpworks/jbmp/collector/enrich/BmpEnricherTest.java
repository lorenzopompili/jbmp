package it.lpworks.jbmp.collector.enrich;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import it.lpworks.jbmp.identity.UuidFactory;
import it.lpworks.jbmp.protocol.bgp.Aggregator;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AsPathSegmentType;
import it.lpworks.jbmp.protocol.bgp.AtomicAggregate;
import it.lpworks.jbmp.protocol.bgp.BgpUpdate;
import it.lpworks.jbmp.protocol.bgp.Communities;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunities;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunity;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bgp.LocalPref;
import it.lpworks.jbmp.protocol.bgp.MpReachNlri;
import it.lpworks.jbmp.protocol.bgp.MultiExitDisc;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginType;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.bmp.PeerDownNotification;
import it.lpworks.jbmp.protocol.bmp.PeerDownReason;
import it.lpworks.jbmp.protocol.bmp.PeerFlags;
import it.lpworks.jbmp.protocol.bmp.PeerType;
import it.lpworks.jbmp.protocol.bmp.PerPeerHeader;
import it.lpworks.jbmp.protocol.bmp.RouteMonitoring;
import it.lpworks.jbmp.protocol.io.ByteWriter;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.PeerEventType;
import it.lpworks.jbmp.wire.RouteAction;
import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * Unit tests for {@link BmpEnricher}, exercising the route-monitor field mapping for IPv4
 * announce/withdraw, an MP_REACH IPv6 announce and a VPNv4 prefix, plus the Peer Down BGP
 * NOTIFICATION decode. No infrastructure is required.
 */
class BmpEnricherTest {

    private static final byte[] ROUTER_IP = {10, 0, 0, 1};
    private static final long RECEIVED_NANOS = 1_700_000_000_000_000_000L;

    private final BmpEnricher enricher = new BmpEnricher();
    private final EnrichmentContext context =
            new EnrichmentContext(ROUTER_IP, 7, () -> RECEIVED_NANOS);

    @Test
    void ipv4AnnounceCarriesFullAttributeSet() throws Exception {
        PerPeerHeader peer = peerHeader(PeerType.GLOBAL_INSTANCE, false, addr("192.0.2.1"), 65001);

        List<PathAttribute> attrs = List.of(
                new Origin(OriginType.IGP),
                new AsPath(List.of(new AsPathSegment(
                        AsPathSegmentType.AS_SEQUENCE, new long[]{65001, 65002, 64500}))),
                new NextHop(addr("192.0.2.254")),
                new MultiExitDisc(50),
                new LocalPref(100),
                new AtomicAggregate(),
                new Aggregator(64500, addr("192.0.2.9")),
                new Communities(new int[]{0x00010002, 0xFFFF0001}),
                new ExtendedCommunities(List.of(
                        routeTarget(64500, 7),                 // sub-type 0x02 => route target
                        new ExtendedCommunity(new byte[]{0x03, 0x0A, 0, 0, 0, 0, 0, 0}))));

        BgpUpdate update = new BgpUpdate(
                List.of(),
                attrs,
                List.of(new IpPrefix(addr("198.51.100.0"), 24)));
        RouteMonitoring rm = new RouteMonitoring(peer, update);

        List<RouteMonitorMessage> out = enricher.enrichRouteMonitoring(rm, context);

        assertThat(out).hasSize(1);
        RouteMonitorMessage msg = out.get(0);

        assertThat(msg.action()).isEqualTo(RouteAction.ANNOUNCE);
        assertThat(msg.ipv4()).isTrue();
        assertThat(msg.endOfRib()).isFalse();
        assertThat(msg.prefixLength()).isEqualTo(24);
        assertThat(msg.prefix()).isEqualTo(addr("198.51.100.0").getAddress());
        assertThat(msg.nextHop()).isEqualTo(addr("192.0.2.254").getAddress());
        assertThat(msg.originAsn()).hasValue(64500);
        assertThat(msg.asPath()).containsExactly(65001, 65002, 64500);
        assertThat(msg.asPathSegments()).hasSize(1);
        assertThat(msg.asPathSegments().get(0).segmentType())
                .isEqualTo(AsPathSegmentType.AS_SEQUENCE.code());
        assertThat(msg.med()).hasValue(50);
        assertThat(msg.localPref()).hasValue(100);
        assertThat(msg.origin()).isEqualTo(OriginType.IGP.code());
        assertThat(msg.atomicAggregate()).isTrue();
        assertThat(msg.aggregatorAsn()).hasValue(64500);
        assertThat(msg.aggregatorAddress()).isEqualTo(addr("192.0.2.9").getAddress());
        assertThat(msg.communities()).containsExactly(0x00010002, 0xFFFF0001);
        assertThat(msg.extendedCommunities()).hasSize(2);
        assertThat(msg.routeTargets()).hasSize(1);
        assertThat(msg.routeTargets().get(0)).isEqualTo(routeTarget(64500, 7).asText());
        assertThat(msg.prePolicy()).isTrue();   // L-flag clear => pre-policy
        assertThat(msg.locRib()).isFalse();

        // Identity and header.
        UUID routerId = UuidFactory.router(ROUTER_IP);
        assertThat(msg.header().routerId()).isEqualTo(routerId);
        assertThat(msg.header().peerId())
                .isEqualTo(UuidFactory.peer(routerId, addr("192.0.2.1").getAddress(), 65001, ""));
        assertThat(msg.header().collectorId()).isEqualTo(7);
        assertThat(msg.header().receivedAtNanos()).isEqualTo(RECEIVED_NANOS);
    }

    @Test
    void ipv4Withdraw() throws Exception {
        PerPeerHeader peer = peerHeader(PeerType.GLOBAL_INSTANCE, true, addr("192.0.2.1"), 65001);
        BgpUpdate update = new BgpUpdate(
                List.of(new IpPrefix(addr("203.0.113.0"), 24)),
                List.of(),
                List.of());
        RouteMonitoring rm = new RouteMonitoring(peer, update);

        List<RouteMonitorMessage> out = enricher.enrichRouteMonitoring(rm, context);

        assertThat(out).hasSize(1);
        RouteMonitorMessage msg = out.get(0);
        assertThat(msg.action()).isEqualTo(RouteAction.WITHDRAW);
        assertThat(msg.ipv4()).isTrue();
        assertThat(msg.prefixLength()).isEqualTo(24);
        assertThat(msg.prefix()).isEqualTo(addr("203.0.113.0").getAddress());
        assertThat(msg.nextHop()).isEmpty();
        assertThat(msg.prePolicy()).isFalse(); // L-flag set => post-policy
    }

    @Test
    void mpReachIpv6Announce() throws Exception {
        PerPeerHeader peer = peerHeader(PeerType.GLOBAL_INSTANCE, false, addr("2001:db8::1"), 65010);

        byte[] nextHop = addr("2001:db8::ffff").getAddress(); // 16 bytes
        byte[] nlri = ipv6Nlri("2001:db8:1::", 48);

        List<PathAttribute> attrs = List.of(
                new Origin(OriginType.IGP),
                new AsPath(List.of(new AsPathSegment(
                        AsPathSegmentType.AS_SEQUENCE, new long[]{65010, 64600}))),
                new MpReachNlri(2, 1, nextHop, nlri)); // AFI IPv6, SAFI unicast

        BgpUpdate update = new BgpUpdate(List.of(), attrs, List.of());
        RouteMonitoring rm = new RouteMonitoring(peer, update);

        List<RouteMonitorMessage> out = enricher.enrichRouteMonitoring(rm, context);

        assertThat(out).hasSize(1);
        RouteMonitorMessage msg = out.get(0);
        assertThat(msg.action()).isEqualTo(RouteAction.ANNOUNCE);
        assertThat(msg.ipv4()).isFalse();
        assertThat(msg.prefixLength()).isEqualTo(48);
        assertThat(msg.prefix()).isEqualTo(addr("2001:db8:1::").getAddress());
        assertThat(msg.nextHop()).isEqualTo(nextHop);
        assertThat(msg.originAsn()).hasValue(64600);
        assertThat(msg.asPath()).containsExactly(65010, 64600);
    }

    @Test
    void vpnv4PrefixCarriesRdAndLabels() throws Exception {
        PerPeerHeader peer = peerHeader(PeerType.GLOBAL_INSTANCE, false, addr("192.0.2.1"), 65001);

        // RD type 0: 2-byte ASN (64500) : 4-byte number (1). VPRN id == low 32 bits == 1.
        byte[] rdValue = {(byte) 0xFB, (byte) 0xF4, 0, 0, 0, 1};
        long label = 24;
        byte[] nlri = vpnv4Nlri(label, 0x00, rdValue, "198.51.100.0", 24);

        byte[] mpNextHop = vpnNextHop(addr("192.0.2.254")); // 8-byte RD + 4-byte IPv4

        List<PathAttribute> attrs = List.of(
                new Origin(OriginType.IGP),
                new MpReachNlri(1, 128, mpNextHop, nlri)); // AFI IPv4, SAFI MPLS VPN

        BgpUpdate update = new BgpUpdate(List.of(), attrs, List.of());
        RouteMonitoring rm = new RouteMonitoring(peer, update);

        List<RouteMonitorMessage> out = enricher.enrichRouteMonitoring(rm, context);

        assertThat(out).hasSize(1);
        RouteMonitorMessage msg = out.get(0);
        assertThat(msg.action()).isEqualTo(RouteAction.ANNOUNCE);
        assertThat(msg.ipv4()).isTrue();
        assertThat(msg.prefixLength()).isEqualTo(24);
        assertThat(msg.prefix()).isEqualTo(addr("198.51.100.0").getAddress());
        assertThat(msg.peerRd()).isEqualTo("64500:1");
        assertThat(msg.vprnId()).isEqualTo(1L);
        assertThat(msg.mplsLabels()).containsExactly(label);
    }

    @Test
    void peerDownDecodesBgpNotification() throws Exception {
        PerPeerHeader peer = peerHeader(PeerType.GLOBAL_INSTANCE, false, addr("192.0.2.1"), 65001);

        // BGP NOTIFICATION: 19-byte header, then code(6=Cease), subcode(2=Admin shutdown), text.
        String text = "maintenance";
        byte[] notification = bgpNotification(6, 2, text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        PeerDownNotification down = new PeerDownNotification(
                peer, 1, PeerDownReason.LOCAL_NOTIFICATION, notification);

        PeerEventMessage msg = enricher.enrichPeerDown(down, context);

        assertThat(msg.eventType()).isEqualTo(PeerEventType.DOWN);
        assertThat(msg.bmpReason()).isEqualTo(1);
        assertThat(msg.bgpErrorCode()).isEqualTo(6);
        assertThat(msg.bgpErrorSubcode()).isEqualTo(2);
        assertThat(msg.errorText()).isEqualTo(text);
        assertThat(msg.remoteAsn()).isEqualTo(65001);
    }

    // ------------------------------------------------------------------
    // Builders / helpers
    // ------------------------------------------------------------------

    private static PerPeerHeader peerHeader(PeerType type, boolean postPolicy,
                                            InetAddress address, long asn) throws Exception {
        boolean ipv6 = !(address instanceof Inet4Address);
        PeerFlags flags = new PeerFlags(ipv6, postPolicy, false);
        return new PerPeerHeader(
                type, flags, new byte[8], address, asn,
                (Inet4Address) addr("192.0.2.200"),
                Instant.ofEpochSecond(1_700_000_000L, 123_000));
    }

    private static ExtendedCommunity routeTarget(int asn, int value) {
        // Type 0x00 (two-octet AS), sub-type 0x02 (Route Target), then ASN(2) + value(4).
        return new ExtendedCommunity(new byte[]{
                0x00, 0x02,
                (byte) (asn >>> 8), (byte) asn,
                (byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value});
    }

    private static byte[] ipv6Nlri(String prefix, int bits) throws Exception {
        byte[] full = addr(prefix).getAddress();
        int significant = (bits + 7) / 8;
        ByteWriter w = new ByteWriter();
        w.writeUint8(bits);
        w.writeBytes(full, 0, significant);
        return w.toByteArray();
    }

    /**
     * Builds one MPLS-VPN NLRI entry per RFC 4364 / RFC 8277, matching the decoder's layout:
     * total length in bits (1 octet), the label stack (3 octets each, bottom-of-stack bit
     * set on the last), the 8-octet RD, then the inner prefix's significant octets.
     */
    private static byte[] vpnv4Nlri(long label, int rdType, byte[] rdValue,
                                    String prefix, int prefixBits) throws Exception {
        int labelBits = 24;
        int rdBits = 64;
        int prefixSigBytes = (prefixBits + 7) / 8;
        int totalBits = labelBits + rdBits + prefixBits;

        ByteWriter w = new ByteWriter();
        w.writeUint8(totalBits);
        // 20-bit label shifted into 3 octets, bottom-of-stack bit set.
        int packed = (int) ((label << 4) | 0x01);
        w.writeUint8((packed >>> 16) & 0xFF);
        w.writeUint8((packed >>> 8) & 0xFF);
        w.writeUint8(packed & 0xFF);
        // 8-octet RD: 2-octet type + 6-octet value.
        w.writeUint16(rdType);
        w.writeBytes(rdValue);
        // Inner prefix significant octets.
        byte[] full = addr(prefix).getAddress();
        w.writeBytes(full, 0, prefixSigBytes);
        return w.toByteArray();
    }

    private static byte[] vpnNextHop(InetAddress ipv4) {
        // RFC 4364: an MPLS-VPN next hop is an 8-octet RD (zero) followed by the IPv4 address.
        byte[] addr = ipv4.getAddress();
        byte[] out = new byte[8 + addr.length];
        System.arraycopy(addr, 0, out, 8, addr.length);
        return out;
    }

    private static byte[] bgpNotification(int code, int subcode, byte[] data) {
        ByteWriter w = new ByteWriter();
        for (int i = 0; i < 16; i++) {
            w.writeUint8(0xFF); // marker
        }
        int length = 19 + 2 + data.length;
        w.writeUint16(length);
        w.writeUint8(3); // NOTIFICATION type
        w.writeUint8(code);
        w.writeUint8(subcode);
        w.writeBytes(data);
        return w.toByteArray();
    }

    private static InetAddress addr(String s) throws UnknownHostException {
        return InetAddress.getByName(s);
    }
}
