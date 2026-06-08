package it.lpworks.jbmp.wire;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.UUID;

import org.junit.jupiter.api.Test;

/**
 * Tests the immutability and array-aware value semantics of the enriched DTOs.
 */
class DtoSemanticsTest {

    private static final MessageHeader HEADER = new MessageHeader(
            1L, 2L, 3, new UUID(1, 2), new UUID(3, 4));

    @Test
    void messageHeaderRejectsNullIdentities() {
        assertThatThrownBy(() -> new MessageHeader(1, 2, 3, null, new UUID(1, 1)))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new MessageHeader(1, 2, 3, new UUID(1, 1), null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void asPathSegmentInfoDefensivelyCopiesAndHasArrayEquality() {
        long[] asns = {1, 2, 3};
        AsPathSegmentInfo seg = new AsPathSegmentInfo(2, asns);
        asns[0] = 999; // mutate caller's array
        assertThat(seg.asns()).containsExactly(1, 2, 3);

        seg.asns()[0] = 777; // mutate returned copy
        assertThat(seg.asns()).containsExactly(1, 2, 3);

        assertThat(seg).isEqualTo(new AsPathSegmentInfo(2, new long[]{1, 2, 3}));
        assertThat(seg).hasSameHashCodeAs(new AsPathSegmentInfo(2, new long[]{1, 2, 3}));
        assertThat(seg).isNotEqualTo(new AsPathSegmentInfo(1, new long[]{1, 2, 3}));
    }

    @Test
    void asPathSegmentInfoNullArrayBecomesEmpty() {
        assertThat(new AsPathSegmentInfo(1, null).asns()).isEmpty();
    }

    @Test
    void routeMonitorNullsBecomeEmptyAndArraysAreCopied() {
        RouteMonitorMessage msg = new RouteMonitorMessage(
                HEADER, RouteAction.ANNOUNCE, false, false, true, false, false,
                null, 0, null, null, null, null, null, null, null, 0, false,
                null, null, null, null, null, null, null, null, 0L, null, null,
                null, null, null, null, null);

        assertThat(msg.prefix()).isEmpty();
        assertThat(msg.nextHop()).isEmpty();
        assertThat(msg.rawNlri()).isEmpty();
        assertThat(msg.asPath()).isEmpty();
        assertThat(msg.communities()).isEmpty();
        assertThat(msg.mplsLabels()).isEmpty();
        assertThat(msg.pathId()).isEmpty();
        assertThat(msg.originatorId()).isEmpty();
        assertThat(msg.peerRd()).isEmpty();
        assertThat(msg.asPathSegments()).isEmpty();
        assertThat(msg.extendedCommunities()).isEmpty();
    }

    @Test
    void routeMonitorMutatingInputDoesNotAffectRecord() {
        byte[] prefix = {1, 2, 3, 4};
        RouteMonitorMessage msg = new RouteMonitorMessage(
                HEADER, RouteAction.ANNOUNCE, false, false, true, false, false,
                prefix, 32, OptionalLong.empty(), OptionalLong.empty(),
                new long[0], List.of(), new byte[0],
                OptionalLong.empty(), OptionalLong.empty(), 0, false,
                OptionalLong.empty(), new byte[0], new int[0], List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0], new byte[0]);
        prefix[0] = 99;
        assertThat(msg.prefix()).containsExactly(1, 2, 3, 4);
    }

    @Test
    void routeMonitorEqualityIsArrayAware() {
        RouteMonitorMessage a = sample(new byte[]{1, 2, 3, 4});
        RouteMonitorMessage b = sample(new byte[]{1, 2, 3, 4});
        RouteMonitorMessage c = sample(new byte[]{9, 9, 9, 9});
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
        assertThat(a).isNotEqualTo(c);
        assertThat(a.toString()).contains("RouteMonitorMessage");
    }

    private static RouteMonitorMessage sample(byte[] prefix) {
        return new RouteMonitorMessage(
                HEADER, RouteAction.ANNOUNCE, false, false, true, false, false,
                prefix, 32, OptionalLong.empty(), OptionalLong.empty(),
                new long[0], List.of(), new byte[]{8, 8, 8, 8},
                OptionalLong.empty(), OptionalLong.empty(), 0, false,
                OptionalLong.empty(), new byte[0], new int[]{5}, List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0], new byte[0]);
    }

    @Test
    void peerEventNullsBecomeEmptyAndArraysAreCopied() {
        byte[] remoteIp = {1, 2, 3, 4};
        PeerEventMessage msg = new PeerEventMessage(
                HEADER, PeerEventType.UP, remoteIp, 1, null, null, 2, null,
                0, 0, null, false, true, false, 0, 0, 0, null, null, null, null);
        remoteIp[0] = 99;
        assertThat(msg.remoteIp()).containsExactly(1, 2, 3, 4);
        assertThat(msg.remoteBgpId()).isEmpty();
        assertThat(msg.peerRd()).isEmpty();
        assertThat(msg.errorText()).isEmpty();
        assertThat(msg.infoData()).isEmpty();
        assertThat(msg.sentOpen()).isEmpty();
    }

    @Test
    void statsReportCopiesAndSortsAndRejectsNullValues() {
        TreeMap<Integer, Long> in = new TreeMap<>();
        in.put(5, 50L);
        in.put(1, 10L);
        StatsReportMessage msg = new StatsReportMessage(HEADER, in);
        in.put(99, 990L); // mutate input after construction
        assertThat(msg.counters()).containsExactly(
                java.util.Map.entry(1, 10L), java.util.Map.entry(5, 50L));
        assertThatThrownBy(() -> msg.counters().put(2, 2L))
                .isInstanceOf(UnsupportedOperationException.class);

        TreeMap<Integer, Long> bad = new TreeMap<>();
        bad.put(1, null);
        assertThatThrownBy(() -> new StatsReportMessage(HEADER, bad))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void routeMirrorCopiesAndHasArrayEquality() {
        byte[] m = {1, 2, 3};
        RouteMirrorMessage msg = new RouteMirrorMessage(HEADER, m, OptionalInt.of(1));
        m[0] = 99;
        assertThat(msg.mirroredMessage()).containsExactly(1, 2, 3);
        assertThat(msg).isEqualTo(new RouteMirrorMessage(HEADER, new byte[]{1, 2, 3}, OptionalInt.of(1)))
                .hasSameHashCodeAs(new RouteMirrorMessage(HEADER, new byte[]{1, 2, 3}, OptionalInt.of(1)));
        assertThat(msg).isNotEqualTo(
                new RouteMirrorMessage(HEADER, new byte[]{1, 2, 3}, OptionalInt.empty()));
    }
}
