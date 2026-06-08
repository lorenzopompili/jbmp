package it.lpworks.jbmp.wire;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.UUID;

import org.junit.jupiter.api.Test;

/**
 * Forward-compatibility tests: a buffer truncated at a trailing (append-only) field must
 * decode cleanly, with the missing trailing fields defaulted to absent/empty. This
 * simulates a newer encoder's output being read by an older decoder (the older decoder
 * stops where its schema ends) and an older encoder's output being read by this decoder
 * (this decoder runs off the end of the buffer and substitutes defaults).
 */
class WireCodecForwardCompatTest {

    private static final MessageHeader HEADER = new MessageHeader(
            1L, 2L, 3, new UUID(10, 20), new UUID(30, 40));

    @Test
    void routeMonitorTruncatedAtTrailingRawNlriDecodesWithEmptyDefault() {
        RouteMonitorMessage msg = new RouteMonitorMessage(
                HEADER, RouteAction.ANNOUNCE, true, false, true, false, false,
                new byte[]{10, 0, 0, 0}, 8, OptionalLong.empty(), OptionalLong.empty(),
                new long[0], List.of(), new byte[0],
                OptionalLong.empty(), OptionalLong.empty(), 0, false,
                OptionalLong.empty(), new byte[0], new int[0], List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0],
                new byte[]{1, 2, 3, 4}); // rawNlri populated

        byte[] full = WireCodec.encodeRouteMonitor(msg);
        // The blob region is the last field. Here only rawNlri is populated, so it is:
        // u8 presence bitmask (0x10) + u32 length (4 bytes) + 4 payload bytes = 9 trailing.
        // Dropping all 9 leaves the buffer ending before the bitmask, which a tolerant
        // decoder reads as "no blobs present" (every blob empty).
        byte[] truncated = Arrays.copyOf(full, full.length - 9);

        RouteMonitorMessage decoded = WireCodec.decodeRouteMonitor(truncated);
        assertThat(decoded.rawNlri()).isEmpty();
        // Everything before the truncation point survives intact.
        assertThat(decoded.prefix()).containsExactly(10, 0, 0, 0);
        assertThat(decoded.prefixLength()).isEqualTo(8);
        assertThat(decoded.linkState()).isEmpty();
    }

    @Test
    void peerEventTruncatedAtTrailingInfoDataDecodesWithEmptyDefault() {
        PeerEventMessage msg = new PeerEventMessage(
                HEADER, PeerEventType.UP,
                new byte[]{1, 2, 3, 4}, 65001, new byte[0],
                new byte[]{5, 6, 7, 8}, 65000, new byte[0],
                179, 50000, "", true, true, false, 0, 0, 0, "",
                new byte[0], new byte[0], "trailing-info");

        byte[] full = WireCodec.encodePeerEvent(msg);
        // infoData is the last field: u16 length (2 bytes) + 13 UTF-8 bytes = 15 trailing.
        byte[] trailing = "trailing-info".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] truncated = Arrays.copyOf(full, full.length - (2 + trailing.length));

        PeerEventMessage decoded = WireCodec.decodePeerEvent(truncated);
        assertThat(decoded.infoData()).isEmpty();
        assertThat(decoded.remoteAsn()).isEqualTo(65001);
        assertThat(decoded.remoteIp()).containsExactly(1, 2, 3, 4);
    }

    @Test
    void routeMirrorTruncatedAtTrailingOptionalFlagDecodesAsAbsent() {
        RouteMirrorMessage msg = new RouteMirrorMessage(
                HEADER, new byte[]{9, 9, 9}, OptionalInt.of(7));
        byte[] full = WireCodec.encodeRouteMirror(msg);
        // Trailing: u8 present flag (1) + u16 value (2) = 3 bytes.
        byte[] truncated = Arrays.copyOf(full, full.length - 3);

        RouteMirrorMessage decoded = WireCodec.decodeRouteMirror(truncated);
        assertThat(decoded.informationCode()).isEmpty();
        assertThat(decoded.mirroredMessage()).containsExactly(9, 9, 9);
    }

    @Test
    void statsReportTruncatedAtCounterBlockDecodesAsEmpty() {
        TreeMap<Integer, Long> counters = new TreeMap<>();
        counters.put(1, 5L);
        StatsReportMessage msg = new StatsReportMessage(HEADER, counters);
        byte[] full = WireCodec.encodeStatsReport(msg);
        // Drop the u16 count and the single counter entry (2 + 2 + 8 = 12 trailing bytes).
        byte[] truncated = Arrays.copyOf(full, full.length - 12);

        StatsReportMessage decoded = WireCodec.decodeStatsReport(truncated);
        assertThat(decoded.counters()).isEmpty();
        assertThat(decoded.header()).isEqualTo(HEADER);
    }
}
