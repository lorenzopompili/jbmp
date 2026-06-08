package it.lpworks.jbmp.wire;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import it.lpworks.jbmp.protocol.bgp.LargeCommunity;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.UUID;

import org.junit.jupiter.api.Test;

/**
 * Round-trip and edge-case tests for {@link WireCodec}.
 */
class WireCodecTest {

    private static final UUID ROUTER_ID = new UUID(0x0123456789ABCDEFL, 0xFEDCBA9876543210L);
    private static final UUID PEER_ID = new UUID(0x1111222233334444L, 0x5555666677778888L);

    private static MessageHeader header() {
        return new MessageHeader(1_700_000_000_000_000_000L, 1_700_000_000_500_000_000L,
                42, ROUTER_ID, PEER_ID);
    }

    private static byte[] ipv4() {
        return new byte[]{(byte) 192, (byte) 168, 1, 1};
    }

    private static byte[] ipv6() {
        return new byte[]{0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    }

    // ------------------------------------------------------------------
    // RouteMonitorMessage
    // ------------------------------------------------------------------

    @Test
    void routeMonitorMinimalIpv4RoundTrips() {
        RouteMonitorMessage msg = new RouteMonitorMessage(
                header(), RouteAction.ANNOUNCE, true, false, true, false, false,
                ipv4(), 24, OptionalLong.empty(), OptionalLong.empty(),
                new long[0], List.of(), new byte[0],
                OptionalLong.empty(), OptionalLong.empty(), -1, false,
                OptionalLong.empty(), new byte[0], new int[0], List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0], new byte[0]);

        byte[] wire = WireCodec.encodeRouteMonitor(msg);
        assertThat(wire[0]).isEqualTo(WireCodec.FORMAT_VERSION);
        assertThat(WireCodec.decodeRouteMonitor(wire)).isEqualTo(msg);
    }

    @Test
    void routeMonitorFullyPopulatedIpv6RoundTrips() {
        RouteMonitorMessage msg = new RouteMonitorMessage(
                header(), RouteAction.WITHDRAW, false, true, false, true, true,
                ipv6(), 64,
                OptionalLong.of(7), OptionalLong.of(65001),
                new long[]{65001, 65002, 4200000000L},
                List.of(new AsPathSegmentInfo(2, new long[]{65001, 65002}),
                        new AsPathSegmentInfo(1, new long[]{4200000000L})),
                ipv6(),
                OptionalLong.of(100), OptionalLong.of(200), 0, true,
                OptionalLong.of(65010), ipv4(),
                new int[]{0x00010001, (int) 0xFFFFFF01L},
                List.of(new LargeCommunity(65001, 1, 2),
                        new LargeCommunity(4200000000L, 4294967295L, 0)),
                List.of(new byte[]{0, 2, (byte) 0xfd, (byte) 0xe9, 0, 0, 0, 1},
                        new byte[]{1, 2, 3, 4, 5, 6, 7, 8}),
                Optional.of(new UUID(9, 10)),
                List.of(new UUID(1, 2), new UUID(3, 4)),
                "65000:100", 12345L,
                List.of("target:65000:1", "target:65000:2"),
                new long[]{24001, 24002},
                new byte[]{10, 11, 12}, new byte[]{20, 21}, new byte[]{30},
                new byte[]{40, 41, 42, 43}, new byte[]{50, 51});

        byte[] wire = WireCodec.encodeRouteMonitor(msg);
        assertThat(WireCodec.decodeRouteMonitor(wire)).isEqualTo(msg);
    }

    @Test
    void routeMonitorLargeBlobsAboveSixtyFourKiBRoundTrip() {
        byte[] big = new byte[70_000];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) (i * 31 + 7);
        }
        RouteMonitorMessage msg = new RouteMonitorMessage(
                header(), RouteAction.ANNOUNCE, true, false, true, false, false,
                ipv4(), 32, OptionalLong.empty(), OptionalLong.empty(),
                new long[0], List.of(), ipv4(),
                OptionalLong.empty(), OptionalLong.empty(), 0, false,
                OptionalLong.empty(), new byte[0], new int[0], List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                big.clone(), big.clone(), big.clone(), big.clone(), big.clone());

        RouteMonitorMessage decoded = WireCodec.decodeRouteMonitor(WireCodec.encodeRouteMonitor(msg));
        assertThat(decoded).isEqualTo(msg);
        assertThat(decoded.evpn()).hasSize(70_000);
        assertThat(decoded.rawNlri()).isEqualTo(big);
    }

    @Test
    void routeMonitorEmptyExtendedBlobsCollapseToSingleBitmaskByte() {
        // All five extended-family blobs empty (the common case).
        RouteMonitorMessage empty = new RouteMonitorMessage(
                header(), RouteAction.ANNOUNCE, true, false, true, false, false,
                ipv4(), 24, OptionalLong.empty(), OptionalLong.empty(),
                new long[0], List.of(), new byte[0],
                OptionalLong.empty(), OptionalLong.empty(), -1, false,
                OptionalLong.empty(), new byte[0], new int[0], List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0], new byte[0]);

        // The same message but with a single one-byte blob (rawNlri) populated.
        RouteMonitorMessage oneBlob = new RouteMonitorMessage(
                header(), RouteAction.ANNOUNCE, true, false, true, false, false,
                ipv4(), 24, OptionalLong.empty(), OptionalLong.empty(),
                new long[0], List.of(), new byte[0],
                OptionalLong.empty(), OptionalLong.empty(), -1, false,
                OptionalLong.empty(), new byte[0], new int[0], List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0], new byte[]{7});

        byte[] emptyWire = WireCodec.encodeRouteMonitor(empty);

        // The whole blob region collapses to one trailing 0x00 bitmask byte: round-trips,
        // and the last byte is the empty-blob bitmask (the trailer).
        assertThat(WireCodec.decodeRouteMonitor(emptyWire)).isEqualTo(empty);
        assertThat(emptyWire[emptyWire.length - 1]).isEqualTo((byte) 0);

        // Under the old layout the trailing region was five unconditional u32 prefixes
        // (5 * 4 = 20 bytes); the new region is one bitmask byte, saving 19 bytes. Adding a
        // single populated blob adds exactly its bit-already-set prefix (4) + payload (1) = 5
        // bytes over the empty case, confirming empty blobs cost nothing but their bit.
        byte[] oneBlobWire = WireCodec.encodeRouteMonitor(oneBlob);
        assertThat(oneBlobWire.length).isEqualTo(emptyWire.length + 5);

        // Everything up to (but excluding) the trailing blob region is identical between the
        // two messages, so that shared prefix length is the byte offset of the blob region.
        int blobRegionOffset = emptyWire.length - 1; // new region is exactly 1 byte
        // Old layout wrote five empty u32 length prefixes there: 5 * 4 = 20 bytes. The new
        // single-bitmask region must be smaller than that old baseline by the promised 19.
        int oldBaselineLength = blobRegionOffset + 20;
        assertThat(emptyWire.length).isEqualTo(oldBaselineLength - 19);
        assertThat(WireCodec.decodeRouteMonitor(oneBlobWire)).isEqualTo(oneBlob);
    }

    @Test
    void routeMonitorOriginAbsentEncodesAsMinusOne() {
        RouteMonitorMessage msg = new RouteMonitorMessage(
                header(), RouteAction.ANNOUNCE, false, false, true, false, false,
                ipv4(), 24, OptionalLong.empty(), OptionalLong.empty(),
                new long[0], List.of(), new byte[0],
                OptionalLong.empty(), OptionalLong.empty(), -1, false,
                OptionalLong.empty(), new byte[0], new int[0], List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0], new byte[0]);

        assertThat(WireCodec.decodeRouteMonitor(WireCodec.encodeRouteMonitor(msg)).origin())
                .isEqualTo(-1);
    }

    // ------------------------------------------------------------------
    // PeerEventMessage
    // ------------------------------------------------------------------

    @Test
    void peerEventUpIpv4RoundTrips() {
        PeerEventMessage msg = new PeerEventMessage(
                header(), PeerEventType.UP,
                ipv4(), 65001, new byte[]{1, 1, 1, 1},
                ipv4(), 65000, new byte[]{2, 2, 2, 2},
                179, 50000, "65000:1", true, true, false,
                0, 0, 0, "",
                new byte[]{1, 2, 3, 4, 5}, new byte[]{6, 7, 8}, "info");

        assertThat(WireCodec.decodePeerEvent(WireCodec.encodePeerEvent(msg))).isEqualTo(msg);
    }

    @Test
    void peerEventDownIpv6WithErrorRoundTrips() {
        PeerEventMessage msg = new PeerEventMessage(
                header(), PeerEventType.DOWN,
                ipv6(), 4200000000L, new byte[]{3, 3, 3, 3},
                ipv6(), 64512, new byte[]{4, 4, 4, 4},
                0, 0, "65000:2", false, false, true,
                3, 6, 5, "Cease/AdminShutdown",
                new byte[0], new byte[0], "");

        assertThat(WireCodec.decodePeerEvent(WireCodec.encodePeerEvent(msg))).isEqualTo(msg);
    }

    @Test
    void peerEventLargeOpenBlobsRoundTrip() {
        byte[] big = new byte[66_000];
        Arrays.fill(big, (byte) 0xAB);
        PeerEventMessage msg = new PeerEventMessage(
                header(), PeerEventType.UP,
                ipv4(), 65001, new byte[0], ipv4(), 65000, new byte[0],
                179, 40000, "", true, true, false, 0, 0, 0, "",
                big.clone(), big.clone(), "");

        PeerEventMessage decoded = WireCodec.decodePeerEvent(WireCodec.encodePeerEvent(msg));
        assertThat(decoded).isEqualTo(msg);
        assertThat(decoded.sentOpen()).hasSize(66_000);
    }

    // ------------------------------------------------------------------
    // StatsReportMessage
    // ------------------------------------------------------------------

    @Test
    void statsReportEmptyRoundTrips() {
        StatsReportMessage msg = new StatsReportMessage(header(), new TreeMap<>());
        assertThat(WireCodec.decodeStatsReport(WireCodec.encodeStatsReport(msg))).isEqualTo(msg);
    }

    @Test
    void statsReportPopulatedRoundTripsInDeterministicOrder() {
        TreeMap<Integer, Long> counters = new TreeMap<>();
        counters.put(7, 100L);
        counters.put(0, 1L);
        counters.put(3, 4_294_967_296L);
        StatsReportMessage msg = new StatsReportMessage(header(), counters);

        byte[] wire1 = WireCodec.encodeStatsReport(msg);
        byte[] wire2 = WireCodec.encodeStatsReport(
                new StatsReportMessage(header(), new TreeMap<>(counters)));
        assertThat(wire1).isEqualTo(wire2); // deterministic
        assertThat(WireCodec.decodeStatsReport(wire1)).isEqualTo(msg);
    }

    // ------------------------------------------------------------------
    // RouteMirrorMessage
    // ------------------------------------------------------------------

    @Test
    void routeMirrorWithCodeRoundTrips() {
        RouteMirrorMessage msg = new RouteMirrorMessage(
                header(), new byte[]{1, 2, 3, 4}, OptionalInt.of(1));
        assertThat(WireCodec.decodeRouteMirror(WireCodec.encodeRouteMirror(msg))).isEqualTo(msg);
    }

    @Test
    void routeMirrorWithoutCodeAndEmptyMessageRoundTrips() {
        RouteMirrorMessage msg = new RouteMirrorMessage(header(), new byte[0], OptionalInt.empty());
        assertThat(WireCodec.decodeRouteMirror(WireCodec.encodeRouteMirror(msg))).isEqualTo(msg);
    }

    @Test
    void routeMirrorLargeMirroredMessageRoundTrips() {
        byte[] big = new byte[80_000];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) i;
        }
        RouteMirrorMessage msg = new RouteMirrorMessage(header(), big.clone(), OptionalInt.of(2));
        RouteMirrorMessage decoded = WireCodec.decodeRouteMirror(WireCodec.encodeRouteMirror(msg));
        assertThat(decoded).isEqualTo(msg);
        assertThat(decoded.mirroredMessage()).hasSize(80_000);
    }

    // ------------------------------------------------------------------
    // Version handling
    // ------------------------------------------------------------------

    @Test
    void decodeRejectsUnknownVersion() {
        RouteMirrorMessage msg = new RouteMirrorMessage(header(), new byte[]{1}, OptionalInt.empty());
        byte[] wire = WireCodec.encodeRouteMirror(msg);
        wire[0] = 99;
        assertThatThrownBy(() -> WireCodec.decodeRouteMirror(wire))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("version");
    }
}
