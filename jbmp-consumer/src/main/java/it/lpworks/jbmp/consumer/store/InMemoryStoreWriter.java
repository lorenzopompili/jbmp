package it.lpworks.jbmp.consumer.store;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteAction;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;

/**
 * An in-memory {@link StoreWriter} that retains everything written to it.
 *
 * <p>It is the default sink for local runs (when no {@code DataSource} is configured) and
 * the assertion surface for unit and embedded-Kafka tests: callers can inspect the appended
 * route-monitor batches, the running peer/stats/mirror records, and the projected
 * {@linkplain #ribState() current routing state} after a flush.
 *
 * <p>All collections are thread-safe so the writer can be shared across the virtual-thread
 * Kafka listener container and test assertion threads.
 */
public final class InMemoryStoreWriter implements StoreWriter {

    private final List<List<RouteMonitorMessage>> routeMonitorBatches = new CopyOnWriteArrayList<>();
    private final List<PeerEventMessage> peerEvents = new CopyOnWriteArrayList<>();
    private final List<StatsReportMessage> stats = new CopyOnWriteArrayList<>();
    private final List<RouteMirrorMessage> routeMirrors = new CopyOnWriteArrayList<>();
    private final Map<RibKey, RouteMonitorMessage> ribState = new ConcurrentHashMap<>();
    private final AtomicLong routeMonitorRowCount = new AtomicLong();

    @Override
    public void writeRouteMonitorBatch(List<RouteMonitorMessage> batch) {
        if (batch.isEmpty()) {
            return;
        }
        routeMonitorBatches.add(List.copyOf(batch));
        routeMonitorRowCount.addAndGet(batch.size());
    }

    @Override
    public void applyRibState(List<RouteMonitorMessage> batch) {
        for (RouteMonitorMessage msg : batch) {
            if (msg.endOfRib()) {
                continue; // End-of-RIB marker carries no NLRI; it does not alter state.
            }
            RibKey key = RibKey.of(msg);
            if (msg.action() == RouteAction.WITHDRAW) {
                ribState.remove(key);
            } else {
                ribState.put(key, msg);
            }
        }
    }

    @Override
    public void writePeerEvent(PeerEventMessage event) {
        peerEvents.add(event);
    }

    @Override
    public void writeStats(StatsReportMessage statsReport) {
        stats.add(statsReport);
    }

    @Override
    public void writeRouteMirror(RouteMirrorMessage mirror) {
        routeMirrors.add(mirror);
    }

    /**
     * Returns the route-monitor batches as they were handed to
     * {@link #writeRouteMonitorBatch(List)}, oldest first.
     *
     * @return an immutable snapshot of the appended batches
     */
    public List<List<RouteMonitorMessage>> routeMonitorBatches() {
        return List.copyOf(routeMonitorBatches);
    }

    /**
     * Returns every route-monitor message that was appended, flattened across all batches in
     * append order.
     *
     * @return an immutable snapshot of all appended route-monitor messages
     */
    public List<RouteMonitorMessage> allRouteMonitorMessages() {
        List<RouteMonitorMessage> all = new ArrayList<>();
        for (List<RouteMonitorMessage> batch : routeMonitorBatches) {
            all.addAll(batch);
        }
        return List.copyOf(all);
    }

    /**
     * Returns the total number of route-monitor rows appended across all batches.
     *
     * @return the cumulative appended row count
     */
    public long routeMonitorRowCount() {
        return routeMonitorRowCount.get();
    }

    /**
     * Returns the recorded peer events in arrival order.
     *
     * @return an immutable snapshot of the peer events
     */
    public List<PeerEventMessage> peerEvents() {
        return List.copyOf(peerEvents);
    }

    /**
     * Returns the recorded statistics reports in arrival order.
     *
     * @return an immutable snapshot of the statistics reports
     */
    public List<StatsReportMessage> stats() {
        return List.copyOf(stats);
    }

    /**
     * Returns the recorded route-mirroring events in arrival order.
     *
     * @return an immutable snapshot of the route-mirroring events
     */
    public List<RouteMirrorMessage> routeMirrors() {
        return List.copyOf(routeMirrors);
    }

    /**
     * Returns the current routing-state projection keyed by {@link RibKey}.
     *
     * @return an immutable snapshot of the current routing state
     */
    public Map<RibKey, RouteMonitorMessage> ribState() {
        return Map.copyOf(ribState);
    }

    /**
     * Clears every retained record and the routing-state projection. Useful between test
     * cases that share a single writer instance.
     */
    public void clear() {
        routeMonitorBatches.clear();
        peerEvents.clear();
        stats.clear();
        routeMirrors.clear();
        ribState.clear();
        routeMonitorRowCount.set(0);
    }
}
