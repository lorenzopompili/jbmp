package it.lpworks.jbmp.mock;

import static org.assertj.core.api.Assertions.assertThat;

import it.lpworks.jbmp.protocol.bgp.Aggregator;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AsPathSegmentType;
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
import it.lpworks.jbmp.protocol.bgp.LinkStateNlri;
import it.lpworks.jbmp.protocol.bgp.LocalPref;
import it.lpworks.jbmp.protocol.bgp.MpReachNlri;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Nlri;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginType;
import it.lpworks.jbmp.protocol.bgp.OriginatorId;
import it.lpworks.jbmp.protocol.bgp.SrPolicyNlri;
import it.lpworks.jbmp.protocol.bgp.VpnPrefix;
import it.lpworks.jbmp.protocol.bmp.BmpMessage;
import it.lpworks.jbmp.protocol.bmp.InitiationMessage;
import it.lpworks.jbmp.protocol.bmp.PeerDownNotification;
import it.lpworks.jbmp.protocol.bmp.PeerUpNotification;
import it.lpworks.jbmp.protocol.bmp.RouteMonitoring;
import it.lpworks.jbmp.protocol.bmp.StatisticsReport;
import it.lpworks.jbmp.protocol.bmp.TerminationMessage;
import it.lpworks.jbmp.protocol.parser.ParseMode;
import it.lpworks.jbmp.protocol.parser.bgp.NlriDecoder;
import it.lpworks.jbmp.protocol.parser.bmp.BmpParser;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ScenarioGenerator}.
 *
 * <p>Every generated message is parsed back with {@link BmpParser} in
 * {@link ParseMode#STRICT}, asserting that the byte stream is RFC-conformant, that the
 * message types arrive in the expected order, that the dump count matches the
 * configuration, and that the Route Monitoring messages carry a parseable
 * {@link BgpUpdate} with the expected attributes (a build-to-parse round-trip). No I/O is
 * performed.
 */
class ScenarioGeneratorTest {

    private static MockProperties props(int routers, int peers, int prefixes,
                                        String scenario, int rate) {
        return new MockProperties(
                "localhost", 1790, routers, peers, prefixes, scenario, rate, false, false);
    }

    private static BmpMessage parse(byte[] message) {
        return BmpParser.parse(message, ParseMode.STRICT);
    }

    @Test
    void everyMessageParsesAndArrivesInOrderForInitialDump() {
        int peers = 2;
        int prefixes = 5;
        ScenarioGenerator generator = new ScenarioGenerator(
                props(1, peers, prefixes, "initial-dump", 0));

        List<byte[]> messages = generator.generateAll(0);
        List<BmpMessage> parsed = messages.stream().map(ScenarioGeneratorTest::parse).toList();

        int i = 0;
        // 1) Initiation.
        assertThat(parsed.get(i++)).isInstanceOf(InitiationMessage.class);
        // 2) One Peer Up per peer.
        for (int p = 0; p < peers; p++) {
            assertThat(parsed.get(i++)).isInstanceOf(PeerUpNotification.class);
        }
        // 3) Per peer: prefixes announcements + 1 End-of-RIB marker.
        for (int p = 0; p < peers; p++) {
            for (int n = 0; n < prefixes; n++) {
                BmpMessage msg = parsed.get(i++);
                assertThat(msg).isInstanceOf(RouteMonitoring.class);
                assertThat(((RouteMonitoring) msg).update().isEndOfRib()).isFalse();
            }
            BmpMessage eor = parsed.get(i++);
            assertThat(eor).isInstanceOf(RouteMonitoring.class);
            assertThat(((RouteMonitoring) eor).update().isEndOfRib()).isTrue();
        }
        // 4) One Statistics Report per peer.
        for (int p = 0; p < peers; p++) {
            assertThat(parsed.get(i++)).isInstanceOf(StatisticsReport.class);
        }
        // initial-dump has no tail beyond the stats.
        assertThat(i).isEqualTo(parsed.size());
    }

    @Test
    void dumpCountMatchesPrefixesPerPeer() {
        int peers = 3;
        int prefixes = 250;
        ScenarioGenerator generator = new ScenarioGenerator(
                props(1, peers, prefixes, "initial-dump", 0));

        List<BmpMessage> parsed =
                generator.generateAll(0).stream().map(ScenarioGeneratorTest::parse).toList();

        long announcements = parsed.stream()
                .filter(RouteMonitoring.class::isInstance)
                .map(RouteMonitoring.class::cast)
                .filter(rm -> !rm.update().isEndOfRib())
                .count();
        long endOfRibs = parsed.stream()
                .filter(RouteMonitoring.class::isInstance)
                .map(RouteMonitoring.class::cast)
                .filter(rm -> rm.update().isEndOfRib())
                .count();

        assertThat(announcements).isEqualTo((long) peers * prefixes);
        assertThat(endOfRibs).isEqualTo(peers);

        long expectedTotal = 1L                         // Initiation
                + peers                                 // Peer Up
                + (long) peers * prefixes + peers       // dump + End-of-RIB
                + peers;                                // Statistics Report
        assertThat(parsed).hasSize((int) expectedTotal);
    }

    @Test
    void routeMonitoringCarriesExpectedAttributes() {
        ScenarioGenerator generator = new ScenarioGenerator(
                props(1, 1, 3, "initial-dump", 0));

        RouteMonitoring firstAnnounce = generator.generateAll(0).stream()
                .map(ScenarioGeneratorTest::parse)
                .filter(RouteMonitoring.class::isInstance)
                .map(RouteMonitoring.class::cast)
                .filter(rm -> !rm.update().isEndOfRib())
                .findFirst()
                .orElseThrow();

        BgpUpdate update = firstAnnounce.update();

        assertThat(update.attribute(Origin.class)).contains(new Origin(OriginType.IGP));
        assertThat(update.attribute(NextHop.class)).isPresent();
        assertThat(update.attribute(LocalPref.class)).contains(new LocalPref(100L));
        assertThat(update.attribute(Communities.class)).isPresent();

        AsPath asPath = update.attribute(AsPath.class).orElseThrow();
        // Upstream, transit, origin (origin AS is a 4-byte documentation ASN).
        assertThat(asPath.length()).isEqualTo(3);
        assertThat(asPath.originAsn()).isPresent();
        assertThat(asPath.originAsn().getAsLong()).isGreaterThan(0xFFFFL);

        assertThat(update.nlri()).hasSize(1);
        IpPrefix prefix = update.nlri().get(0);
        assertThat(prefix.prefixLength()).isEqualTo(24);

        // Peer header sanity: post-policy flag set, non-zero timestamp survives parsing.
        assertThat(firstAnnounce.peerHeader().flags().postPolicy()).isTrue();
        assertThat(firstAnnounce.peerHeader().timestamp().getEpochSecond()).isGreaterThan(0L);
    }

    @Test
    void incrementalScenarioEmitsAnnounceAndWithdrawChurn() {
        int rate = 4;
        ScenarioGenerator generator = new ScenarioGenerator(
                props(1, 1, 2, "incremental", rate));

        List<BmpMessage> parsed =
                generator.generateAll(0).stream().map(ScenarioGeneratorTest::parse).toList();

        long withdraws = parsed.stream()
                .filter(RouteMonitoring.class::isInstance)
                .map(RouteMonitoring.class::cast)
                .filter(rm -> !rm.update().withdrawnRoutes().isEmpty())
                .count();
        // One withdraw per churn message pair.
        assertThat(withdraws).isEqualTo(rate);

        // No teardown in the plain incremental scenario.
        assertThat(parsed).noneMatch(PeerDownNotification.class::isInstance);
        assertThat(parsed).noneMatch(TerminationMessage.class::isInstance);
    }

    @Test
    void fullLifecycleScenarioTearsTheSessionDown() {
        int peers = 2;
        ScenarioGenerator generator = new ScenarioGenerator(
                props(1, peers, 2, "full-lifecycle", 2));

        List<BmpMessage> parsed =
                generator.generateAll(0).stream().map(ScenarioGeneratorTest::parse).toList();

        long peerDowns = parsed.stream().filter(PeerDownNotification.class::isInstance).count();
        assertThat(peerDowns).isEqualTo(peers);
        assertThat(parsed.get(parsed.size() - 1)).isInstanceOf(TerminationMessage.class);
    }

    @Test
    void distinctRoutersProduceDistinctPeerAddresses() {
        ScenarioGenerator generator = new ScenarioGenerator(
                props(2, 1, 1, "initial-dump", 0));

        PeerUpNotification routerZeroPeer = firstPeerUp(generator.generateAll(0));
        PeerUpNotification routerOnePeer = firstPeerUp(generator.generateAll(1));

        assertThat(routerZeroPeer.peerHeader().address())
                .isNotEqualTo(routerOnePeer.peerHeader().address());
        assertThat(routerZeroPeer.peerHeader().peerAsn())
                .isNotEqualTo(routerOnePeer.peerHeader().peerAsn());
    }

    private static PeerUpNotification firstPeerUp(List<byte[]> messages) {
        return messages.stream()
                .map(ScenarioGeneratorTest::parse)
                .filter(PeerUpNotification.class::isInstance)
                .map(PeerUpNotification.class::cast)
                .findFirst()
                .orElseThrow();
    }

    // ------------------------------------------------------------------
    // STRESS scenario: the full attribute mix
    // ------------------------------------------------------------------

    /**
     * Collects every announce {@link BgpUpdate} (excluding End-of-RIB and withdrawals) from
     * a freshly-generated {@code stress} dump, parsing every message in
     * {@link ParseMode#STRICT} so the assertions also prove RFC conformance of the bytes.
     */
    private static List<BgpUpdate> stressAnnounces(int prefixes) {
        ScenarioGenerator generator = new ScenarioGenerator(props(1, 1, prefixes, "stress", 4));
        return generator.generateAll(0).stream()
                .map(ScenarioGeneratorTest::parse)
                .filter(RouteMonitoring.class::isInstance)
                .map(RouteMonitoring.class::cast)
                .map(RouteMonitoring::update)
                .filter(u -> !u.isEndOfRib() && u.withdrawnRoutes().isEmpty())
                .toList();
    }

    @Test
    void stressScenarioCarriesTheFullStandardAttributeMix() {
        List<BgpUpdate> announces = stressAnnounces(400);

        // Multi-segment AS_PATHs including the occasional AS_SET / AS_CONFED_SEQUENCE.
        boolean sawMultiSegment = false;
        boolean sawAsSet = false;
        boolean sawConfed = false;
        for (BgpUpdate u : announces) {
            AsPath asPath = u.attribute(AsPath.class).orElse(null);
            if (asPath == null) {
                continue;
            }
            if (asPath.segments().size() > 1) {
                sawMultiSegment = true;
            }
            for (AsPathSegment seg : asPath.segments()) {
                if (seg.type() == AsPathSegmentType.AS_SET) {
                    sawAsSet = true;
                }
                if (seg.type() == AsPathSegmentType.AS_CONFED_SEQUENCE) {
                    sawConfed = true;
                }
            }
        }
        assertThat(sawMultiSegment).as("a multi-segment AS_PATH appears").isTrue();
        assertThat(sawAsSet).as("an AS_SET segment appears").isTrue();
        assertThat(sawConfed).as("an AS_CONFED_SEQUENCE segment appears").isTrue();

        // The well-known transitive attributes are universal.
        assertThat(announces).allMatch(u -> u.attribute(Origin.class).isPresent());
        assertThat(announces).allMatch(u -> u.attribute(AsPath.class).isPresent());

        // ATOMIC_AGGREGATE + AGGREGATOR appear on a fraction.
        assertThat(announces).anyMatch(u -> u.attribute(AtomicAggregate.class).isPresent());
        assertThat(announces).anyMatch(u -> u.attribute(Aggregator.class).isPresent());

        // Route-reflector attributes appear on a fraction.
        assertThat(announces).anyMatch(u -> u.attribute(OriginatorId.class).isPresent());
        assertThat(announces).anyMatch(u -> u.attribute(ClusterList.class).isPresent());

        // Standard, large and extended communities all appear.
        assertThat(announces).anyMatch(u -> u.attribute(Communities.class).isPresent());
        assertThat(announces).anyMatch(u -> u.attribute(LargeCommunities.class).isPresent());
        assertThat(announces).anyMatch(u -> u.attribute(ExtendedCommunities.class).isPresent());

        // A route-target extended community appears somewhere in the stream.
        boolean sawRouteTarget = announces.stream()
                .map(u -> u.attribute(ExtendedCommunities.class).orElse(null))
                .filter(ec -> ec != null)
                .flatMap(ec -> ec.communities().stream())
                .anyMatch(ExtendedCommunity::isRouteTarget);
        assertThat(sawRouteTarget).as("a Route Target extended community appears").isTrue();
    }

    @Test
    void stressScenarioCarriesEveryMultiprotocolFamily() {
        List<BgpUpdate> announces = stressAnnounces(400);

        // Decode the MP_REACH NLRI of every multiprotocol announce and collect the
        // address-family classes that appear.
        Set<Class<?>> families = new HashSet<>();
        boolean sawL3vpnRouteTarget = false;
        for (BgpUpdate u : announces) {
            MpReachNlri mp = u.attribute(MpReachNlri.class).orElse(null);
            if (mp == null) {
                continue;
            }
            List<Nlri> decoded = NlriDecoder.decode(mp.afi(), mp.safi(), mp.nlri(), false);
            for (Nlri nlri : decoded) {
                families.add(nlri.getClass());
            }
            // An L3VPN route must carry a Route Target (RFC 4364 §4.3.1).
            if (decoded.stream().anyMatch(VpnPrefix.class::isInstance)) {
                sawL3vpnRouteTarget = u.attribute(ExtendedCommunities.class)
                        .map(ec -> ec.communities().stream().anyMatch(ExtendedCommunity::isRouteTarget))
                        .orElse(false);
            }
        }

        assertThat(families).contains(
                VpnPrefix.class,       // L3VPN (RFC 4364)
                EvpnRoute.class,       // EVPN (RFC 7432)
                FlowSpecRule.class,    // Flow Specification (RFC 8955)
                SrPolicyNlri.class,    // SR Policy
                LinkStateNlri.class);  // BGP-LS (RFC 7752)
        assertThat(sawL3vpnRouteTarget).as("the L3VPN route carries a Route Target").isTrue();
    }

    @Test
    void stressScenarioRemainsDeterministic() {
        ScenarioGenerator a = new ScenarioGenerator(props(1, 2, 60, "stress", 4));
        ScenarioGenerator b = new ScenarioGenerator(props(1, 2, 60, "stress", 4));

        List<byte[]> first = a.generateAll(0);
        List<byte[]> second = b.generateAll(0);

        assertThat(first).hasSameSizeAs(second);
        for (int i = 0; i < first.size(); i++) {
            assertThat(first.get(i)).as("message %d is byte-identical", i)
                    .isEqualTo(second.get(i));
        }
    }

    @Test
    void stressScenarioStillWithdrawsAndTearsDown() {
        ScenarioGenerator generator = new ScenarioGenerator(props(1, 2, 30, "stress", 3));
        List<BmpMessage> parsed =
                generator.generateAll(0).stream().map(ScenarioGeneratorTest::parse).toList();

        long withdraws = parsed.stream()
                .filter(RouteMonitoring.class::isInstance)
                .map(RouteMonitoring.class::cast)
                .filter(rm -> !rm.update().withdrawnRoutes().isEmpty())
                .count();
        assertThat(withdraws).isGreaterThan(0L);

        // STRESS includes a graceful teardown (Peer Down per peer + Termination).
        assertThat(parsed).anyMatch(PeerDownNotification.class::isInstance);
        assertThat(parsed.get(parsed.size() - 1)).isInstanceOf(TerminationMessage.class);
    }

    @Test
    void stressVanillaFirstPrefixMatchesTheBaseline() {
        // The first prefix of every peer stays pinned to the vanilla baseline even under
        // the full attribute mix, giving a stable, well-known reference route.
        BgpUpdate first = stressAnnounces(60).get(0);
        assertThat(first.attribute(Origin.class)).contains(new Origin(OriginType.IGP));
        assertThat(first.attribute(LocalPref.class)).contains(new LocalPref(100L));
        assertThat(first.attribute(NextHop.class)).isPresent();
        assertThat(first.attribute(AsPath.class).orElseThrow().length()).isEqualTo(3);
        assertThat(first.nlri()).hasSize(1);
        IpPrefix prefix = first.nlri().get(0);
        assertThat(prefix.prefixLength()).isEqualTo(24);
    }
}
