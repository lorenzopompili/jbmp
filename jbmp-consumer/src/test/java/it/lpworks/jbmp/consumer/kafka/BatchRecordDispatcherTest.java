package it.lpworks.jbmp.consumer.kafka;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import it.lpworks.jbmp.consumer.TestMessages;
import it.lpworks.jbmp.consumer.config.ConsumerProperties;
import it.lpworks.jbmp.consumer.dump.DumpDetector;
import it.lpworks.jbmp.consumer.store.RibKey;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;
import it.lpworks.jbmp.wire.WireCodec;
import it.lpworks.jbmp.consumer.store.StoreWriter;

/**
 * Unit tests for {@link BatchRecordDispatcher}: it decodes a mixed poll batch by topic, routes
 * every route-monitor record into a single {@link StoreWriter#writeRouteMonitorBatch(List)} +
 * {@link StoreWriter#applyRibState(List)} pair, writes the single-message topics individually,
 * and tracks the End-of-RIB transition on the {@link DumpDetector}. Exercised entirely without
 * Kafka, using hand-built encoded records and a recording fake store.
 */
class BatchRecordDispatcherTest {

    private static final UUID PEER = TestMessages.peer(1);

    private ConsumerProperties.Topics topics;
    private RecordingStoreWriter store;
    private DumpDetector dumpDetector;
    private BatchRecordDispatcher dispatcher;

    @BeforeEach
    void setUp() {
        topics = new ConsumerProperties.Topics("rm.v4", "rm.v6", "peers", "stats", "mirror");
        store = new RecordingStoreWriter();
        dumpDetector = new DumpDetector();
        // The rib-state sink is invoked synchronously here (store::applyRibState) so the
        // recorded call order still reflects the projection write; in production it is the
        // asynchronous RibStateWorker.
        dispatcher = new BatchRecordDispatcher(topics, dumpDetector, store, store::applyRibState);
    }

    private static ConsumerRecord<byte[], byte[]> record(String topic, byte[] value) {
        return new ConsumerRecord<>(topic, 0, 0L, null, value);
    }

    @Test
    void mixedBatchRoutesRouteMonitorsToBatchAndSinglesToTheirWriters() {
        List<ConsumerRecord<byte[], byte[]>> batch = List.of(
                record("rm.v4", WireCodec.encodeRouteMonitor(TestMessages.announce(PEER, 1))),
                record("peers", WireCodec.encodePeerEvent(TestMessages.peerUp(PEER))),
                record("rm.v6", WireCodec.encodeRouteMonitor(TestMessages.announce(PEER, 2))),
                record("stats", WireCodec.encodeStatsReport(TestMessages.stats(PEER))),
                record("mirror", WireCodec.encodeRouteMirror(TestMessages.routeMirror(PEER))));

        dispatcher.writeBatch(batch);

        // Both route-monitor families landed in a single route-monitor batch write...
        assertThat(store.routeMonitorBatches).hasSize(1);
        assertThat(store.routeMonitorBatches.getFirst()).hasSize(2);
        // ...and the RIB projection was applied to that same batch.
        assertThat(store.ribBatches).hasSize(1);
        assertThat(store.ribBatches.getFirst()).hasSize(2);
        assertThat(store.ribKeys()).hasSize(2);

        // The three single-message topics were each written once.
        assertThat(store.peerEvents).hasSize(1);
        assertThat(store.stats).hasSize(1);
        assertThat(store.routeMirrors).hasSize(1);

        // The peer was observed and (no End-of-RIB seen) is still in the initial-dump state.
        assertThat(dumpDetector.isInDump(PEER)).isTrue();
    }

    @Test
    void routeMonitorBatchWriteHappensAfterTheSingleMessageWrites() {
        List<ConsumerRecord<byte[], byte[]>> batch = List.of(
                record("rm.v4", WireCodec.encodeRouteMonitor(TestMessages.announce(PEER, 1))),
                record("peers", WireCodec.encodePeerEvent(TestMessages.peerUp(PEER))));

        dispatcher.writeBatch(batch);

        // The whole poll is persisted before the caller commits; the route-monitor batch write
        // is the last store call, so on a clean return every record is durable.
        assertThat(store.callLog)
                .containsExactly("writePeerEvent", "writeRouteMonitorBatch", "applyRibState");
    }

    @Test
    void endOfRibClearsTheDumpStateForThePeer() {
        List<ConsumerRecord<byte[], byte[]>> batch = List.of(
                record("rm.v4", WireCodec.encodeRouteMonitor(TestMessages.announce(PEER, 1))),
                record("rm.v4", WireCodec.encodeRouteMonitor(TestMessages.endOfRib(PEER))));

        dispatcher.writeBatch(batch);

        assertThat(dumpDetector.isInDump(PEER)).isFalse();
        // The End-of-RIB marker carries no NLRI, so the RIB projection holds only the announce.
        assertThat(store.ribKeys()).hasSize(1);
    }

    @Test
    void batchWithoutRouteMonitorsSkipsTheRouteMonitorWrites() {
        List<ConsumerRecord<byte[], byte[]>> batch = List.of(
                record("peers", WireCodec.encodePeerEvent(TestMessages.peerUp(PEER))),
                record("stats", WireCodec.encodeStatsReport(TestMessages.stats(PEER))));

        dispatcher.writeBatch(batch);

        assertThat(store.routeMonitorBatches).isEmpty();
        assertThat(store.ribBatches).isEmpty();
        assertThat(store.callLog).containsExactly("writePeerEvent", "writeStats");
    }

    @Test
    void emptyBatchIsANoOp() {
        dispatcher.writeBatch(List.of());

        assertThat(store.callLog).isEmpty();
    }

    @Test
    void unconfiguredTopicIsRejected() {
        List<ConsumerRecord<byte[], byte[]>> batch = List.of(
                record("unknown", WireCodec.encodeStatsReport(TestMessages.stats(PEER))));

        assertThatThrownBy(() -> dispatcher.writeBatch(batch))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unknown");
    }

    /**
     * A recording {@link StoreWriter} that captures, in order, every store method it was asked
     * to perform along with the batches it was handed. It can also be primed to throw from
     * {@link #writeRouteMonitorBatch(List)} so a failed write can be asserted against.
     */
    static final class RecordingStoreWriter implements StoreWriter {

        final List<String> callLog = new ArrayList<>();
        final List<List<RouteMonitorMessage>> routeMonitorBatches = new ArrayList<>();
        final List<List<RouteMonitorMessage>> ribBatches = new ArrayList<>();
        final List<PeerEventMessage> peerEvents = new ArrayList<>();
        final List<StatsReportMessage> stats = new ArrayList<>();
        final List<RouteMirrorMessage> routeMirrors = new ArrayList<>();

        boolean failRouteMonitorWrite;

        @Override
        public void writeRouteMonitorBatch(List<RouteMonitorMessage> batch) {
            callLog.add("writeRouteMonitorBatch");
            if (failRouteMonitorWrite) {
                throw new IllegalStateException("store unavailable");
            }
            routeMonitorBatches.add(List.copyOf(batch));
        }

        @Override
        public void applyRibState(List<RouteMonitorMessage> batch) {
            callLog.add("applyRibState");
            ribBatches.add(List.copyOf(batch));
        }

        @Override
        public void writePeerEvent(PeerEventMessage event) {
            callLog.add("writePeerEvent");
            peerEvents.add(event);
        }

        @Override
        public void writeStats(StatsReportMessage statsReport) {
            callLog.add("writeStats");
            stats.add(statsReport);
        }

        @Override
        public void writeRouteMirror(RouteMirrorMessage mirror) {
            callLog.add("writeRouteMirror");
            routeMirrors.add(mirror);
        }

        /** The distinct RIB keys announced (non-withdrawn) across all applied batches. */
        List<RibKey> ribKeys() {
            List<RibKey> keys = new ArrayList<>();
            for (List<RouteMonitorMessage> batch : ribBatches) {
                for (RouteMonitorMessage msg : batch) {
                    if (!msg.endOfRib()) {
                        keys.add(RibKey.of(msg));
                    }
                }
            }
            return keys;
        }
    }
}
