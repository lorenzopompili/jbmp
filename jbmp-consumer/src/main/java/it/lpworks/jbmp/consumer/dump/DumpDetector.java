package it.lpworks.jbmp.consumer.dump;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * Tracks, per monitored peer, whether the initial table dump is still in progress.
 *
 * <p>When a BMP session for a peer comes up, the router replays its entire Adj-RIB / Loc-RIB
 * as a burst of Route Monitoring messages before transitioning to incremental updates. RFC
 * 4724 (Graceful Restart) defines an <em>End-of-RIB</em> marker — an UPDATE with no
 * reachability information — that BMP carries to signal the end of that initial dump for an
 * AFI/SAFI. This detector flips a peer into the "in dump" state on its first route-monitor
 * message and clears it when an {@linkplain RouteMonitorMessage#endOfRib() End-of-RIB} for
 * that peer is observed, letting downstream logic distinguish the high-volume initial load
 * from steady-state churn.
 *
 * <p>The detector is thread-safe so a single instance can be shared across the (potentially
 * virtual-thread) Kafka listener container.
 */
public final class DumpDetector {

    /** Peers currently believed to be replaying their initial table dump. */
    private final Set<UUID> inDump = ConcurrentHashMap.newKeySet();

    /**
     * Records the observation of one route-monitoring message and updates the peer's dump
     * state accordingly.
     *
     * <p>The first route-monitor message seen for a peer marks it as in-dump; an End-of-RIB
     * marker clears it. An End-of-RIB seen for a peer that was not yet tracked simply leaves
     * the peer out of the in-dump set (a no-op), which is the correct steady-state outcome.
     *
     * @param msg the route-monitoring message (never {@code null})
     * @return {@code true} if, after applying this message, the peer is in the initial-dump
     *         state; {@code false} otherwise
     * @throws NullPointerException if {@code msg} is {@code null}
     */
    public boolean observe(RouteMonitorMessage msg) {
        Objects.requireNonNull(msg, "msg");
        UUID peerId = msg.header().peerId();
        if (msg.endOfRib()) {
            inDump.remove(peerId);
            return false;
        }
        inDump.add(peerId);
        return true;
    }

    /**
     * Returns whether the given peer is currently replaying its initial table dump.
     *
     * @param peerId the peer identity to query (never {@code null})
     * @return {@code true} if the peer is in the initial-dump state
     * @throws NullPointerException if {@code peerId} is {@code null}
     */
    public boolean isInDump(UUID peerId) {
        Objects.requireNonNull(peerId, "peerId");
        return inDump.contains(peerId);
    }

    /**
     * Returns the number of peers currently in the initial-dump state.
     *
     * @return the count of in-dump peers
     */
    public int inDumpCount() {
        return inDump.size();
    }

    /**
     * Forgets all tracked peers. Intended for a full reset (e.g. on a consumer rebalance
     * that reassigns every partition, or between test cases).
     */
    public void reset() {
        inDump.clear();
    }
}
