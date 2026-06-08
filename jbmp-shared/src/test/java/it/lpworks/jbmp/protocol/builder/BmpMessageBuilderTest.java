package it.lpworks.jbmp.protocol.builder;

import static org.assertj.core.api.Assertions.assertThat;

import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AsPathSegmentType;
import it.lpworks.jbmp.protocol.bgp.BgpUpdate;
import it.lpworks.jbmp.protocol.bgp.Communities;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bgp.LargeCommunities;
import it.lpworks.jbmp.protocol.bgp.LargeCommunity;
import it.lpworks.jbmp.protocol.bgp.LocalPref;
import it.lpworks.jbmp.protocol.bgp.MultiExitDisc;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginType;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
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
import it.lpworks.jbmp.protocol.bmp.stat.DuplicateUpdates;
import it.lpworks.jbmp.protocol.bmp.stat.LocRibRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.PrefixesRejected;
import it.lpworks.jbmp.protocol.bmp.stat.StatCounter;
import it.lpworks.jbmp.protocol.bmp.stat.UnknownStat;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationType;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationType;
import it.lpworks.jbmp.protocol.parser.ParseMode;
import it.lpworks.jbmp.protocol.parser.bmp.BmpParser;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.OptionalInt;

import org.junit.jupiter.api.Test;

/**
 * Round-trip unit tests for {@link BmpMessageBuilder}: each test builds a BMP message
 * and parses it back with {@link BmpParser} in {@link ParseMode#STRICT}, asserting the
 * decoded model equals the inputs. This cross-validates the builder against the parser.
 *
 * <p>Per-peer headers use non-zero, microsecond-aligned timestamps so they survive the
 * parser's {@code (sec == 0 && micros == 0) -> Instant.now()} fallback and its
 * microsecond reconstruction.
 */
class BmpMessageBuilderTest {

    /** A fixed, microsecond-precise, in-uint32-range timestamp. */
    private static final Instant TS = Instant.ofEpochSecond(1_700_000_000L, 123_456_000L);

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    private static Inet4Address v4(String s) {
        try {
            return (Inet4Address) InetAddress.getByName(s);
        } catch (UnknownHostException e) {
            throw new AssertionError(e);
        }
    }

    private static Inet6Address v6(String s) {
        try {
            return (Inet6Address) InetAddress.getByName(s);
        } catch (UnknownHostException e) {
            throw new AssertionError(e);
        }
    }

    /** Builds an IPv4 per-peer header (V flag clear). */
    private static PerPeerHeader peerV4() {
        return new PerPeerHeader(
                PeerType.GLOBAL_INSTANCE,
                new PeerFlags(false, true, false),
                new byte[] {0, 0, 0, 0, 0, 0, 0, 1},
                v4("192.0.2.1"),
                65001L,
                v4("10.0.0.1"),
                TS);
    }

    /** Builds an IPv6 per-peer header (V flag set). */
    private static PerPeerHeader peerV6() {
        return new PerPeerHeader(
                PeerType.RD_INSTANCE,
                new PeerFlags(true, false, false),
                new byte[] {0, 0, 0, 0, 0, 0, 0, 2},
                v6("2001:db8::1"),
                4200000000L,
                v4("10.0.0.2"),
                TS);
    }

    /** Builds a minimal, self-framed BGP OPEN message (19-octet header only). */
    private static byte[] openMessage() {
        byte[] open = new byte[19];
        for (int i = 0; i < 16; i++) {
            open[i] = (byte) 0xFF; // Marker.
        }
        open[16] = 0x00;
        open[17] = 0x13; // Length = 19.
        open[18] = 0x01; // Type = OPEN.
        return open;
    }

    private static BmpMessage parse(byte[] message) {
        return BmpParser.parse(message, ParseMode.STRICT);
    }

    // ------------------------------------------------------------------
    // Per-peer header round-trips
    // ------------------------------------------------------------------

    @Test
    void ipv4PeerHeaderRoundTrips() {
        PerPeerHeader peer = peerV4();
        byte[] bytes = BmpMessageBuilder.peerDown(peer, 1, new byte[0]);
        PeerDownNotification down = (PeerDownNotification) parse(bytes);

        assertThat(down.peerHeader()).isEqualTo(peer);
        assertThat(down.peerHeader().address()).isEqualTo(v4("192.0.2.1"));
        assertThat(down.peerHeader().timestamp()).isEqualTo(TS);
    }

    @Test
    void ipv6PeerHeaderRoundTrips() {
        PerPeerHeader peer = peerV6();
        byte[] bytes = BmpMessageBuilder.peerDown(peer, 4, new byte[0]);
        PeerDownNotification down = (PeerDownNotification) parse(bytes);

        assertThat(down.peerHeader()).isEqualTo(peer);
        assertThat(down.peerHeader().address()).isEqualTo(v6("2001:db8::1"));
    }

    // ------------------------------------------------------------------
    // Type 4: Initiation
    // ------------------------------------------------------------------

    @Test
    void initiationRoundTrips() {
        List<InformationTlv> tlvs = List.of(
                new InformationTlv(InformationType.SYS_NAME, InformationType.SYS_NAME.code(),
                        "router-1".getBytes(StandardCharsets.UTF_8)),
                new InformationTlv(InformationType.SYS_DESCR, InformationType.SYS_DESCR.code(),
                        "test box".getBytes(StandardCharsets.UTF_8)),
                new InformationTlv(InformationType.UNKNOWN, 999, new byte[] {9, 9}));

        byte[] bytes = BmpMessageBuilder.initiation(tlvs);
        InitiationMessage msg = (InitiationMessage) parse(bytes);

        assertThat(msg.type()).isEqualTo(BmpMessageType.INITIATION);
        assertThat(msg.informationTlvs()).containsExactlyElementsOf(tlvs);
    }

    // ------------------------------------------------------------------
    // Type 5: Termination
    // ------------------------------------------------------------------

    @Test
    void terminationRoundTrips() {
        List<TerminationTlv> tlvs = List.of(
                new TerminationTlv(TerminationType.STRING, TerminationType.STRING.code(),
                        "bye".getBytes(StandardCharsets.UTF_8)),
                new TerminationTlv(TerminationType.REASON, TerminationType.REASON.code(),
                        new byte[] {0x00, 0x01}));

        byte[] bytes = BmpMessageBuilder.termination(tlvs);
        TerminationMessage msg = (TerminationMessage) parse(bytes);

        assertThat(msg.tlvs()).containsExactlyElementsOf(tlvs);
    }

    // ------------------------------------------------------------------
    // Type 0: Route Monitoring (carrying a full BGP UPDATE)
    // ------------------------------------------------------------------

    @Test
    void routeMonitoringWithFullUpdateRoundTrips() {
        AsPath asPath = new AsPath(List.of(
                new AsPathSegment(AsPathSegmentType.AS_SEQUENCE,
                        new long[] {65536L, 4200000000L}),
                new AsPathSegment(AsPathSegmentType.AS_SET,
                        new long[] {65010L, 65011L})));

        List<PathAttribute> attributes = List.of(
                new Origin(OriginType.IGP),
                asPath,
                new NextHop(v4("192.0.2.254")),
                new MultiExitDisc(50L),
                new LocalPref(150L),
                new Communities(new int[] {0x00640001, 0x00640002}),
                new LargeCommunities(List.of(new LargeCommunity(65536L, 7L, 8L))));

        List<IpPrefix> nlri = List.of(
                new IpPrefix(v4("198.51.100.0"), 24),
                new IpPrefix(v4("203.0.113.0"), 24));

        // Peer uses 4-byte AS_PATH (A flag clear); builder and parser must agree.
        PerPeerHeader peer = peerV4();
        byte[] bgp = BgpUpdateBuilder.update(List.of(), attributes, nlri, false);
        byte[] bytes = BmpMessageBuilder.routeMonitoring(peer, bgp);

        RouteMonitoring msg = (RouteMonitoring) parse(bytes);
        BgpUpdate update = msg.update();

        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(update.pathAttributes()).containsExactlyElementsOf(attributes);
        assertThat(update.nlri()).containsExactlyElementsOf(nlri);
    }

    @Test
    void routeMonitoringWith2ByteAsPathRoundTrips() {
        AsPath asPath = new AsPath(List.of(
                new AsPathSegment(AsPathSegmentType.AS_SEQUENCE,
                        new long[] {65001L, 65002L})));
        List<PathAttribute> attributes = List.of(new Origin(OriginType.IGP), asPath);

        // Peer with A flag set => 2-byte AS_PATH; builder must encode AS as 2 octets.
        PerPeerHeader peer = new PerPeerHeader(
                PeerType.GLOBAL_INSTANCE,
                new PeerFlags(false, false, true),
                new byte[8],
                v4("192.0.2.5"),
                65001L,
                v4("10.0.0.5"),
                TS);

        byte[] bgp = BgpUpdateBuilder.update(List.of(), attributes, List.of(), true);
        byte[] bytes = BmpMessageBuilder.routeMonitoring(peer, bgp);

        RouteMonitoring msg = (RouteMonitoring) parse(bytes);
        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(msg.update().pathAttributes()).containsExactlyElementsOf(attributes);
    }

    // ------------------------------------------------------------------
    // Type 1: Statistics Report
    // ------------------------------------------------------------------

    @Test
    void statisticsReportRoundTrips() {
        List<StatCounter> counters = List.of(
                new PrefixesRejected(42L),
                new DuplicateUpdates(7L),
                new AdjRibInRoutes(0x0000_0001_0000_0000L),
                new LocRibRoutes(123456789L),
                new UnknownStat(250, new byte[] {0x0A, 0x0B, 0x0C}));

        PerPeerHeader peer = peerV4();
        byte[] bytes = BmpMessageBuilder.statisticsReport(peer, counters);
        StatisticsReport msg = (StatisticsReport) parse(bytes);

        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(msg.counters()).containsExactlyElementsOf(counters);
    }

    @Test
    void emptyStatisticsReportRoundTrips() {
        PerPeerHeader peer = peerV6();
        byte[] bytes = BmpMessageBuilder.statisticsReport(peer, List.of());
        StatisticsReport msg = (StatisticsReport) parse(bytes);

        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(msg.counters()).isEmpty();
    }

    // ------------------------------------------------------------------
    // Type 3: Peer Up
    // ------------------------------------------------------------------

    @Test
    void peerUpRoundTrips() {
        PerPeerHeader peer = peerV4();
        byte[] sent = openMessage();
        byte[] received = openMessage();
        List<InformationTlv> tlvs = List.of(
                new InformationTlv(InformationType.STRING, InformationType.STRING.code(),
                        "up".getBytes(StandardCharsets.UTF_8)));

        byte[] bytes = BmpMessageBuilder.peerUp(
                peer, v4("192.0.2.100"), 179, 50000, sent, received, tlvs);
        PeerUpNotification msg = (PeerUpNotification) parse(bytes);

        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(msg.localAddress()).isEqualTo(v4("192.0.2.100"));
        assertThat(msg.localPort()).isEqualTo(179);
        assertThat(msg.remotePort()).isEqualTo(50000);
        assertThat(msg.sentOpenMessage()).isEqualTo(sent);
        assertThat(msg.receivedOpenMessage()).isEqualTo(received);
        assertThat(msg.informationTlvs()).containsExactlyElementsOf(tlvs);
    }

    @Test
    void peerUpIpv6LocalAddressRoundTrips() {
        PerPeerHeader peer = peerV6();
        byte[] open = openMessage();

        byte[] bytes = BmpMessageBuilder.peerUp(
                peer, v6("2001:db8::abcd"), 179, 60000, open, open, List.of());
        PeerUpNotification msg = (PeerUpNotification) parse(bytes);

        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(msg.localAddress()).isEqualTo(v6("2001:db8::abcd"));
    }

    // ------------------------------------------------------------------
    // Type 2: Peer Down
    // ------------------------------------------------------------------

    @Test
    void peerDownWithNotificationRoundTrips() {
        PerPeerHeader peer = peerV4();
        byte[] notification = new byte[] {0x06, 0x04, 0x01, 0x02}; // arbitrary payload
        byte[] bytes = BmpMessageBuilder.peerDown(peer, 1, notification);
        PeerDownNotification msg = (PeerDownNotification) parse(bytes);

        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(msg.reasonCode()).isEqualTo(1);
        assertThat(msg.reason()).isEqualTo(PeerDownReason.LOCAL_NOTIFICATION);
        assertThat(msg.data()).isEqualTo(notification);
    }

    @Test
    void peerDownFsmReasonRoundTrips() {
        PerPeerHeader peer = peerV4();
        byte[] fsm = new byte[] {0x00, 0x05}; // 2-octet FSM event code
        byte[] bytes = BmpMessageBuilder.peerDown(peer, 2, fsm);
        PeerDownNotification msg = (PeerDownNotification) parse(bytes);

        assertThat(msg.reasonCode()).isEqualTo(2);
        assertThat(msg.reason()).isEqualTo(PeerDownReason.LOCAL_FSM);
        assertThat(msg.data()).isEqualTo(fsm);
    }

    // ------------------------------------------------------------------
    // Type 6: Route Mirroring
    // ------------------------------------------------------------------

    @Test
    void routeMirroringWithMessageAndCodeRoundTrips() {
        PerPeerHeader peer = peerV4();
        byte[] mirrored = openMessage();
        byte[] bytes = BmpMessageBuilder.routeMirroring(peer, mirrored, OptionalInt.of(1));
        RouteMirroring msg = (RouteMirroring) parse(bytes);

        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(msg.mirroredBgpMessage()).isEqualTo(mirrored);
        assertThat(msg.informationCode()).hasValue(1);
    }

    @Test
    void routeMirroringMessageOnlyRoundTrips() {
        PerPeerHeader peer = peerV6();
        byte[] mirrored = openMessage();
        byte[] bytes = BmpMessageBuilder.routeMirroring(peer, mirrored, OptionalInt.empty());
        RouteMirroring msg = (RouteMirroring) parse(bytes);

        assertThat(msg.peerHeader()).isEqualTo(peer);
        assertThat(msg.mirroredBgpMessage()).isEqualTo(mirrored);
        assertThat(msg.informationCode()).isEmpty();
    }
}
