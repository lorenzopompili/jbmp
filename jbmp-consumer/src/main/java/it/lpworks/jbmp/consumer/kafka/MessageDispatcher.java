package it.lpworks.jbmp.consumer.kafka;

import java.util.Objects;

import it.lpworks.jbmp.consumer.batch.BatchAccumulator;
import it.lpworks.jbmp.consumer.config.ConsumerProperties;
import it.lpworks.jbmp.consumer.dump.DumpDetector;
import it.lpworks.jbmp.consumer.store.StoreWriter;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;
import it.lpworks.jbmp.wire.WireCodec;

/**
 * The framework-free decode-and-dispatch core of the consumer.
 *
 * <p>Given a source topic and the raw Kafka record value, it selects the matching {@link
 * WireCodec} {@code decodeX} method and routes the decoded message to the appropriate sink:
 * <ul>
 *   <li><b>route-monitor</b> messages (the IPv4 and IPv6 topics) are fed to the {@link
 *       BatchAccumulator}, which owns the flush/commit lifecycle, and are also observed by
 *       the {@link DumpDetector}. The supplied offset token is committed by the accumulator
 *       only after a successful batch flush;</li>
 *   <li><b>peer-event</b>, <b>stats</b> and <b>route-mirror</b> messages are low-volume and
 *       written individually and synchronously to the {@link StoreWriter}; their offset token
 *       is committed immediately on a successful write via the {@code singleCommit}
 *       callback.</li>
 * </ul>
 *
 * <p>The class is deliberately Spring- and Kafka-free so the routing decisions can be unit
 * tested by feeding raw bytes and asserting on an in-memory store. Any decode or store
 * failure propagates so the caller can withhold the offset commit.
 *
 * @param <T> the offset-token type threaded through the batching engine
 */
public final class MessageDispatcher<T> {

    private final ConsumerProperties.Topics topics;
    private final BatchAccumulator<T> accumulator;
    private final DumpDetector dumpDetector;
    private final StoreWriter store;

    /**
     * Creates a dispatcher.
     *
     * @param topics       the configured topic names used to classify the source (never
     *                     {@code null})
     * @param accumulator  the route-monitor batching engine (never {@code null})
     * @param dumpDetector the per-peer initial-dump tracker (never {@code null})
     * @param store        the sink for the single-message (non-batched) topics (never
     *                     {@code null})
     * @throws NullPointerException if any argument is {@code null}
     */
    public MessageDispatcher(ConsumerProperties.Topics topics, BatchAccumulator<T> accumulator,
            DumpDetector dumpDetector, StoreWriter store) {
        this.topics = Objects.requireNonNull(topics, "topics");
        this.accumulator = Objects.requireNonNull(accumulator, "accumulator");
        this.dumpDetector = Objects.requireNonNull(dumpDetector, "dumpDetector");
        this.store = Objects.requireNonNull(store, "store");
    }

    /**
     * Decodes one Kafka record value and dispatches it according to its source topic.
     *
     * @param topic        the topic the record came from (never {@code null})
     * @param value        the raw, codec-encoded record value (never {@code null})
     * @param token        the offset token for this record (never {@code null})
     * @param singleCommit the callback invoked to commit the offset of a successfully written
     *                     single-message record; not used for route-monitor records, whose
     *                     commit is owned by the {@link BatchAccumulator} (never {@code null})
     * @throws IllegalArgumentException if {@code topic} is not a configured consumer topic, or
     *                                  if the bytes fail to decode
     * @throws RuntimeException         if a store write fails (the caller must withhold the
     *                                  offset commit)
     */
    public void dispatch(String topic, byte[] value, T token, Runnable singleCommit) {
        Objects.requireNonNull(topic, "topic");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(singleCommit, "singleCommit");

        if (topics.isRouteMonitor(topic)) {
            RouteMonitorMessage msg = WireCodec.decodeRouteMonitor(value);
            dumpDetector.observe(msg);
            accumulator.add(msg, token);
            return;
        }
        if (topic.equals(topics.peerEvents())) {
            PeerEventMessage msg = WireCodec.decodePeerEvent(value);
            store.writePeerEvent(msg);
            singleCommit.run();
            return;
        }
        if (topic.equals(topics.stats())) {
            StatsReportMessage msg = WireCodec.decodeStatsReport(value);
            store.writeStats(msg);
            singleCommit.run();
            return;
        }
        if (topic.equals(topics.routeMirror())) {
            RouteMirrorMessage msg = WireCodec.decodeRouteMirror(value);
            store.writeRouteMirror(msg);
            singleCommit.run();
            return;
        }
        throw new IllegalArgumentException("Record received from unconfigured topic: " + topic);
    }
}
