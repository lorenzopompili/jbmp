package it.lpworks.jbmp.consumer;

import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.OptionalLong;
import java.util.TreeMap;
import java.util.UUID;

import it.lpworks.jbmp.wire.MessageHeader;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.PeerEventType;
import it.lpworks.jbmp.wire.RouteAction;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;

/**
 * Factory helpers that build minimal, valid wire DTOs for the consumer's unit and
 * integration tests. Keeping construction in one place avoids repeating the long
 * {@link RouteMonitorMessage} constructor across tests.
 */
public final class TestMessages {

    /** A stable router identity used across the test fixtures. */
    public static final UUID ROUTER_ID = new UUID(0xAAAAAAAAAAAAAAAAL, 0xBBBBBBBBBBBBBBBBL);

    private TestMessages() {
        throw new AssertionError("No instances");
    }

    /**
     * Builds a deterministic peer identity for the given numeric seed.
     *
     * @param seed the seed mixed into the peer UUID
     * @return a peer UUID
     */
    public static UUID peer(long seed) {
        return new UUID(0xCCCCCCCC00000000L | seed, 0xDDDDDDDD00000000L | seed);
    }

    private static MessageHeader header(UUID peerId, long eventTime) {
        return new MessageHeader(eventTime, eventTime + 1, 7, ROUTER_ID, peerId);
    }

    /**
     * Builds an IPv4 announce for {@code 10.0.0.0/24} (varying the third octet by index) from
     * the given peer.
     *
     * @param peerId the originating peer
     * @param index  varies the prefix so successive calls produce distinct routes
     * @return a route-monitoring announce message
     */
    public static RouteMonitorMessage announce(UUID peerId, int index) {
        return route(peerId, RouteAction.ANNOUNCE, index, false);
    }

    /**
     * Builds an IPv4 withdraw matching {@link #announce(UUID, int)} for the same index.
     *
     * @param peerId the originating peer
     * @param index  the prefix index to withdraw
     * @return a route-monitoring withdraw message
     */
    public static RouteMonitorMessage withdraw(UUID peerId, int index) {
        return route(peerId, RouteAction.WITHDRAW, index, false);
    }

    /**
     * Builds an End-of-RIB marker for the given peer (RFC 4724).
     *
     * @param peerId the peer whose initial dump has completed
     * @return an end-of-RIB route-monitoring message
     */
    public static RouteMonitorMessage endOfRib(UUID peerId) {
        return route(peerId, RouteAction.ANNOUNCE, 0, true);
    }

    private static RouteMonitorMessage route(UUID peerId, RouteAction action, int index,
            boolean endOfRib) {
        byte[] prefix = endOfRib ? new byte[0] : new byte[]{10, 0, (byte) index, 0};
        int prefixLen = endOfRib ? 0 : 24;
        return new RouteMonitorMessage(
                header(peerId, 1_000_000_000L + index), action,
                true, false, true, endOfRib, false,
                prefix, prefixLen, OptionalLong.empty(), OptionalLong.of(65000),
                new long[]{65000}, List.of(), new byte[]{(byte) 192, (byte) 168, 0, 1},
                OptionalLong.empty(), OptionalLong.empty(), 0, false,
                OptionalLong.empty(), new byte[0], new int[0], List.of(), List.of(),
                Optional.empty(), List.of(), "", 0L, List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0], new byte[0]);
    }

    /**
     * Builds a peer-up event for the given peer.
     *
     * @param peerId the peer that came up
     * @return a peer-event message
     */
    public static PeerEventMessage peerUp(UUID peerId) {
        return new PeerEventMessage(
                header(peerId, 2_000_000_000L), PeerEventType.UP,
                new byte[]{10, 0, 0, 2}, 65001L, new byte[]{1, 1, 1, 1},
                new byte[]{10, 0, 0, 1}, 65000L, new byte[]{2, 2, 2, 2},
                179, 50000, "", true, true, false,
                0, 0, 0, "", new byte[0], new byte[0], "");
    }

    /**
     * Builds a statistics report carrying a single counter for the given peer.
     *
     * @param peerId the peer the report concerns
     * @return a stats-report message
     */
    public static StatsReportMessage stats(UUID peerId) {
        TreeMap<Integer, Long> counters = new TreeMap<>();
        counters.put(0, 42L); // Stat Type 0: rejected prefixes (RFC 7854 §4.8)
        return new StatsReportMessage(header(peerId, 3_000_000_000L), counters);
    }

    /**
     * Builds a route-mirroring event for the given peer.
     *
     * @param peerId the peer the mirrored PDU was observed on
     * @return a route-mirror message
     */
    public static RouteMirrorMessage routeMirror(UUID peerId) {
        return new RouteMirrorMessage(
                header(peerId, 4_000_000_000L), new byte[]{1, 2, 3, 4}, OptionalInt.of(1));
    }
}
