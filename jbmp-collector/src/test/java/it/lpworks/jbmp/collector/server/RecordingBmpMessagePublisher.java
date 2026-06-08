package it.lpworks.jbmp.collector.server;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;

import it.lpworks.jbmp.collector.publish.BmpMessagePublisher;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;

/**
 * An in-memory {@link BmpMessagePublisher} that records every published message and counts
 * down a {@link CountDownLatch} per typed publish, so a test can await a known number of
 * successful publishes without sleeping. Raw publishes are recorded but do not count toward
 * the latch.
 */
final class RecordingBmpMessagePublisher implements BmpMessagePublisher {

    private final CountDownLatch latch;

    private final List<RouteMonitorMessage> routeMonitors = new CopyOnWriteArrayList<>();
    private final List<PeerEventMessage> peerEvents = new CopyOnWriteArrayList<>();
    private final List<StatsReportMessage> stats = new CopyOnWriteArrayList<>();
    private final List<RouteMirrorMessage> routeMirrors = new CopyOnWriteArrayList<>();
    private final List<UUID> rawRouterIds = new CopyOnWriteArrayList<>();

    /**
     * @param expectedTypedPublishes the number of typed (non-raw) publishes to await
     */
    RecordingBmpMessagePublisher(int expectedTypedPublishes) {
        this.latch = new CountDownLatch(expectedTypedPublishes);
    }

    CountDownLatch latch() {
        return latch;
    }

    List<RouteMonitorMessage> routeMonitors() {
        return routeMonitors;
    }

    List<PeerEventMessage> peerEvents() {
        return peerEvents;
    }

    List<StatsReportMessage> stats() {
        return stats;
    }

    List<RouteMirrorMessage> routeMirrors() {
        return routeMirrors;
    }

    List<UUID> rawRouterIds() {
        return rawRouterIds;
    }

    @Override
    public void publishRouteMonitor(RouteMonitorMessage message) {
        routeMonitors.add(message);
        latch.countDown();
    }

    @Override
    public void publishPeerEvent(PeerEventMessage message) {
        peerEvents.add(message);
        latch.countDown();
    }

    @Override
    public void publishStats(StatsReportMessage message) {
        stats.add(message);
        latch.countDown();
    }

    @Override
    public void publishRouteMirror(RouteMirrorMessage message) {
        routeMirrors.add(message);
        latch.countDown();
    }

    @Override
    public void publishRaw(UUID routerId, byte[] rawBmpMessage) {
        rawRouterIds.add(routerId);
    }
}
