package it.lpworks.jbmp.protocol.builder;

import static org.assertj.core.api.Assertions.assertThat;

import it.lpworks.jbmp.protocol.bgp.Aggregator;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AsPathSegmentType;
import it.lpworks.jbmp.protocol.bgp.AtomicAggregate;
import it.lpworks.jbmp.protocol.bgp.BgpUpdate;
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
import it.lpworks.jbmp.protocol.bgp.OriginType;
import it.lpworks.jbmp.protocol.bgp.OriginatorId;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.bgp.UnknownAttribute;
import it.lpworks.jbmp.protocol.io.ByteReader;
import it.lpworks.jbmp.protocol.parser.ParseMode;
import it.lpworks.jbmp.protocol.parser.bgp.BgpUpdateParser;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Round-trip unit tests for {@link BgpUpdateBuilder}: each test builds a BGP UPDATE
 * and parses it back with {@link BgpUpdateParser}, asserting the decoded model equals
 * the inputs. This cross-validates the builder against the parser.
 */
class BgpUpdateBuilderTest {

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

    private static BgpUpdate roundTrip(byte[] message, boolean asPath2Byte) {
        return BgpUpdateParser.parse(new ByteReader(message), ParseMode.STRICT, asPath2Byte);
    }

    @Test
    void emptyUpdateRoundTrips() {
        byte[] bytes = BgpUpdateBuilder.update(List.of(), List.of(), List.of(), false);
        BgpUpdate update = roundTrip(bytes, false);

        assertThat(update.withdrawnRoutes()).isEmpty();
        assertThat(update.pathAttributes()).isEmpty();
        assertThat(update.nlri()).isEmpty();
        assertThat(update.isEndOfRib()).isTrue();
    }

    @Test
    void withdrawnAndNlriPrefixesRoundTrip() {
        List<IpPrefix> withdrawn = List.of(
                new IpPrefix(v4("10.0.0.0"), 8),
                new IpPrefix(v4("192.168.1.0"), 24));
        List<IpPrefix> nlri = List.of(
                new IpPrefix(v4("172.16.0.0"), 12),
                new IpPrefix(v4("203.0.113.42"), 32),
                new IpPrefix(v4("0.0.0.0"), 0));

        byte[] bytes = BgpUpdateBuilder.update(withdrawn, List.of(), nlri, false);
        BgpUpdate update = roundTrip(bytes, false);

        assertThat(update.withdrawnRoutes()).containsExactlyElementsOf(withdrawn);
        assertThat(update.nlri()).containsExactlyElementsOf(nlri);
    }

    @Test
    void fullAttributeSetWith4ByteAsRoundTrips() {
        AsPath asPath = new AsPath(List.of(
                new AsPathSegment(AsPathSegmentType.AS_SEQUENCE,
                        new long[] {65536L, 4200000000L, 64500L}),
                new AsPathSegment(AsPathSegmentType.AS_SET,
                        new long[] {65001L, 65002L})));

        List<PathAttribute> attributes = List.of(
                new Origin(OriginType.IGP),
                asPath,
                new NextHop(v4("192.0.2.1")),
                new MultiExitDisc(100L),
                new LocalPref(200L),
                new Communities(new int[] {0x00010002, 0xFFFF0001}),
                new LargeCommunities(List.of(
                        new LargeCommunity(65536L, 1L, 2L),
                        new LargeCommunity(4200000000L, 3L, 4L))));

        List<IpPrefix> nlri = List.of(new IpPrefix(v4("198.51.100.0"), 24));

        byte[] bytes = BgpUpdateBuilder.update(List.of(), attributes, nlri, false);
        BgpUpdate update = roundTrip(bytes, false);

        assertThat(update.pathAttributes()).containsExactlyElementsOf(attributes);
        assertThat(update.nlri()).containsExactlyElementsOf(nlri);
        assertThat(update.attribute(AsPath.class)).contains(asPath);
    }

    @Test
    void asPath2ByteEncodingRoundTrips() {
        AsPath asPath = new AsPath(List.of(
                new AsPathSegment(AsPathSegmentType.AS_SEQUENCE,
                        new long[] {65001L, 65002L, 65003L})));
        List<PathAttribute> attributes = List.of(new Origin(OriginType.EGP), asPath);

        // Built and parsed both as 2-byte AS_PATH.
        byte[] bytes = BgpUpdateBuilder.update(List.of(), attributes, List.of(), true);
        BgpUpdate update = roundTrip(bytes, true);

        assertThat(update.pathAttributes()).containsExactlyElementsOf(attributes);
    }

    @Test
    void aggregator4ByteRoundTrips() {
        Aggregator aggregator = new Aggregator(4200000000L, v4("192.0.2.9"));
        List<PathAttribute> attributes = List.of(
                new Origin(OriginType.INCOMPLETE),
                new AtomicAggregate(),
                aggregator);

        byte[] bytes = BgpUpdateBuilder.update(List.of(), attributes, List.of(), false);
        BgpUpdate update = roundTrip(bytes, false);

        assertThat(update.pathAttributes()).containsExactlyElementsOf(attributes);
        assertThat(update.attribute(Aggregator.class)).contains(aggregator);
    }

    @Test
    void aggregator2ByteRoundTrips() {
        Aggregator aggregator = new Aggregator(64512L, v4("192.0.2.10"));
        List<PathAttribute> attributes = List.of(aggregator);

        byte[] bytes = BgpUpdateBuilder.update(List.of(), attributes, List.of(), true);
        BgpUpdate update = roundTrip(bytes, true);

        assertThat(update.attribute(Aggregator.class)).contains(aggregator);
    }

    @Test
    void routeReflectionAndExtendedCommunitiesRoundTrip() {
        OriginatorId originatorId = new OriginatorId(v4("10.1.2.3"));
        ClusterList clusterList = new ClusterList(List.of(v4("10.0.0.1"), v4("10.0.0.2")));
        ExtendedCommunities ext = new ExtendedCommunities(List.of(
                new ExtendedCommunity(new byte[] {0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64}),
                new ExtendedCommunity(new byte[] {0x40, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})));

        List<PathAttribute> attributes = List.of(
                new Origin(OriginType.IGP), originatorId, clusterList, ext);

        byte[] bytes = BgpUpdateBuilder.update(List.of(), attributes, List.of(), false);
        BgpUpdate update = roundTrip(bytes, false);

        assertThat(update.pathAttributes()).containsExactlyElementsOf(attributes);
    }

    @Test
    void mpReachAndUnreachRoundTrip() {
        // IPv6 unicast next-hop and a hand-built NLRI blob (kept raw by the model).
        byte[] nextHop = v6("2001:db8::1").getAddress();
        byte[] reachNlri = new byte[] {0x40, 0x20, 0x01, 0x0d, (byte) 0xb8, 0x00, 0x00, 0x01};
        byte[] unreachNlri = new byte[] {0x30, 0x20, 0x01, 0x0d, (byte) 0xb8, 0x00};

        MpReachNlri mpReach = new MpReachNlri(2, 1, nextHop, reachNlri);
        MpUnreachNlri mpUnreach = new MpUnreachNlri(2, 1, unreachNlri);

        List<PathAttribute> attributes = List.of(new Origin(OriginType.IGP), mpReach, mpUnreach);

        byte[] bytes = BgpUpdateBuilder.update(List.of(), attributes, List.of(), false);
        BgpUpdate update = roundTrip(bytes, false);

        assertThat(update.pathAttributes()).containsExactlyElementsOf(attributes);
        assertThat(update.attribute(MpReachNlri.class)).contains(mpReach);
        assertThat(update.attribute(MpUnreachNlri.class)).contains(mpUnreach);
    }

    @Test
    void unknownAttributeRoundTripsVerbatim() {
        UnknownAttribute unknown = new UnknownAttribute(
                200,
                it.lpworks.jbmp.protocol.bgp.AttributeFlags.fromByte(0xC0),
                new byte[] {0x01, 0x02, 0x03, 0x04, 0x05});
        List<PathAttribute> attributes = List.of(new Origin(OriginType.IGP), unknown);

        byte[] bytes = BgpUpdateBuilder.update(List.of(), attributes, List.of(), false);
        BgpUpdate update = roundTrip(bytes, false);

        assertThat(update.pathAttributes()).containsExactlyElementsOf(attributes);
    }

    @Test
    void extendedLengthAttributeRoundTrips() {
        // A COMMUNITIES attribute with > 255 value octets forces extended-length flag.
        int count = 80; // 80 * 4 = 320 octets of value.
        int[] values = new int[count];
        for (int i = 0; i < count; i++) {
            values[i] = (0x0001 << 16) | (i & 0xFFFF);
        }
        Communities communities = new Communities(values);
        List<PathAttribute> attributes = List.of(communities);

        byte[] bytes = BgpUpdateBuilder.update(List.of(), attributes, List.of(), false);
        BgpUpdate update = roundTrip(bytes, false);

        assertThat(update.attribute(Communities.class)).contains(communities);
    }
}
