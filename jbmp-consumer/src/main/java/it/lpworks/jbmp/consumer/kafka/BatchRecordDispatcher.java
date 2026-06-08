package it.lpworks.jbmp.consumer.kafka;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import org.apache.kafka.clients.consumer.ConsumerRecord;

import it.lpworks.jbmp.consumer.config.ConsumerProperties;
import it.lpworks.jbmp.consumer.dump.DumpDetector;
import it.lpworks.jbmp.consumer.store.StoreWriter;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;
import it.lpworks.jbmp.wire.WireCodec;

/**
 * The framework-free, decode-and-write core of the parallel batch consumer.
 *
 * <p>Given the records of a single Kafka poll (which may span several partitions of the five
 * subscribed topics), {@link #writeBatch(List)} decodes each record with the {@link WireCodec}
 * {@code decodeX} method selected by its source topic and persists the whole poll to the
 * {@link StoreWriter}:
 * <ul>
 *   <li><b>route-monitor</b> records (the IPv4 and IPv6 topics) are decoded and collected into
 *       one list that is written in two store calls — {@link
 *       StoreWriter#writeRouteMonitorBatch(List) the historical append} followed by {@link
 *       StoreWriter#applyRibState(List) the idempotent RIB projection} — and each is also
 *       observed by the {@link DumpDetector} so the End-of-RIB transition is tracked;</li>
 *   <li><b>peer-event</b>, <b>stats</b> and <b>route-mirror</b> records are lower-volume and are
 *       decoded, collected per type, and written one batch per type (so a bursty dump does not
 *       pay a transaction per message).</li>
 * </ul>
 *
 * <h2>Offset-after-write</h2>
 * <p>{@link #writeBatch(List)} performs only the decode and the store writes; it never touches
 * Kafka offsets. The caller ({@link KafkaIngestService}) acknowledges the poll batch only when
 * this method returns normally, so an offset is committed strictly after the corresponding rows
 * are durably written. Any decode or store failure propagates, the caller withholds the commit,
 * and Kafka re-delivers the batch.
 *
 * <h2>Thread-safety</h2>
 * <p>The dispatcher holds no per-call mutable state: each invocation allocates its own local
 * route-monitor list, so the {@code N} container threads can call {@link #writeBatch(List)}
 * concurrently. The only shared collaborators are the {@link StoreWriter} (thread-safe by
 * contract — every call uses its own connection) and the {@link DumpDetector} (backed by a
 * concurrent set). There is no shared accumulator funnelling every partition through one lock.
 */
public final class BatchRecordDispatcher {

    private final ConsumerProperties.Topics topics;
    private final DumpDetector dumpDetector;
    private final StoreWriter store;
    private final Consumer<List<RouteMonitorMessage>> ribStateSink;

    /**
     * Creates a batch dispatcher.
     *
     * @param topics       the configured topic names used to classify each record's source
     *                     (never {@code null})
     * @param dumpDetector the per-peer initial-dump tracker (never {@code null})
     * @param store        the persistence sink (never {@code null})
     * @param ribStateSink the sink that applies the {@code rib_state} projection for each
     *                     flushed route-monitor batch — typically an asynchronous worker so the
     *                     projection runs off the offset-commit path (never {@code null})
     * @throws NullPointerException if any argument is {@code null}
     */
    public BatchRecordDispatcher(ConsumerProperties.Topics topics, DumpDetector dumpDetector,
            StoreWriter store, Consumer<List<RouteMonitorMessage>> ribStateSink) {
        this.topics = Objects.requireNonNull(topics, "topics");
        this.dumpDetector = Objects.requireNonNull(dumpDetector, "dumpDetector");
        this.store = Objects.requireNonNull(store, "store");
        this.ribStateSink = Objects.requireNonNull(ribStateSink, "ribStateSink");
    }

    /**
     * Decodes and persists one poll batch of Kafka records.
     *
     * <p>Route-monitor records from both families are gathered into a single list and written
     * with one {@link StoreWriter#writeRouteMonitorBatch(List)} + {@link
     * StoreWriter#applyRibState(List)} pair; the three single-message topics are decoded and
     * written one record at a time. The route-monitor writes happen after the per-record
     * single-message writes so that, on success, the whole poll has been persisted before the
     * caller commits its offsets.
     *
     * @param records the records returned by a single {@code poll()} (never {@code null}; may
     *                be empty, in which case the call is a no-op)
     * @throws NullPointerException     if {@code records} is {@code null}
     * @throws IllegalArgumentException if a record comes from an unconfigured topic, or its
     *                                  bytes fail to decode
     * @throws RuntimeException         if a store write fails (the caller must withhold the
     *                                  offset commit)
     */
    public void writeBatch(List<ConsumerRecord<byte[], byte[]>> records) {
        Objects.requireNonNull(records, "records");
        if (records.isEmpty()) {
            return;
        }

        List<RouteMonitorMessage> routeMonitors = new ArrayList<>(records.size());
        // Kafka provenance per route-monitor row (aligned with routeMonitors); only the leading
        // routeMonitors.size() entries are used.
        int[] partitions = new int[records.size()];
        long[] offsets = new long[records.size()];
        List<PeerEventMessage> peerEvents = new ArrayList<>();
        List<StatsReportMessage> stats = new ArrayList<>();
        List<RouteMirrorMessage> mirrors = new ArrayList<>();

        for (ConsumerRecord<byte[], byte[]> record : records) {
            String topic = record.topic();
            byte[] value = record.value();
            if (topics.isRouteMonitor(topic)) {
                RouteMonitorMessage msg = WireCodec.decodeRouteMonitor(value);
                dumpDetector.observe(msg);
                partitions[routeMonitors.size()] = record.partition();
                offsets[routeMonitors.size()] = record.offset();
                routeMonitors.add(msg);
            } else if (topic.equals(topics.peerEvents())) {
                peerEvents.add(WireCodec.decodePeerEvent(value));
            } else if (topic.equals(topics.stats())) {
                stats.add(WireCodec.decodeStatsReport(value));
            } else if (topic.equals(topics.routeMirror())) {
                mirrors.add(WireCodec.decodeRouteMirror(value));
            } else {
                throw new IllegalArgumentException(
                        "Record received from unconfigured topic: " + topic);
            }
        }

        // Single-message topics are low-volume but bursty (an initial dump brings up every peer
        // at once); writing them per record would pay one transaction per message and serialise
        // the thread that owns those partitions. They are batched into one write per type, ahead
        // of the route-monitor history so the whole poll is durable before the caller commits.
        if (!peerEvents.isEmpty()) {
            store.writePeerEvents(peerEvents);
        }
        if (!stats.isEmpty()) {
            store.writeStatsBatch(stats);
        }
        if (!mirrors.isEmpty()) {
            store.writeRouteMirrors(mirrors);
        }

        if (!routeMonitors.isEmpty()) {
            // The append-only history is written synchronously so the caller's offset commit
            // happens strictly after it is durable; the rebuildable rib_state projection is
            // handed off to run off the commit path.
            store.writeRouteMonitorBatch(routeMonitors, partitions, offsets);
            ribStateSink.accept(routeMonitors);
        }
    }
}
