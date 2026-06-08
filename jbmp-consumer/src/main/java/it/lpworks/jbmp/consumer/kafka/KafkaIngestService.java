package it.lpworks.jbmp.consumer.kafka;

import java.util.List;
import java.util.Objects;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

/**
 * The Kafka entry point of the consumer: a parallel, batch-mode listener tuned for maximum
 * ingest throughput.
 *
 * <p>The five topics are consumed by <strong>two separate listener containers</strong> in the
 * same consumer group, so the high-volume historical path never shares a thread with the
 * low-volume writers:
 * <ul>
 *   <li>{@link #onRouteMonitorBatch(List, Acknowledgment)} consumes only the two route-monitor
 *       topics on {@code jbmp.consumer.concurrency} threads — each poll is a pure bulk
 *       {@code COPY} + RIB projection;</li>
 *   <li>{@link #onAuxBatch(List, Acknowledgment)} consumes the peer-event, stats and
 *       route-mirror topics on a small, separate thread pool — its per-message/batched writes
 *       run in parallel and can never block a route-monitor {@code COPY} (no head-of-line
 *       blocking of the hot path behind a burst of statistics reports).</li>
 * </ul>
 * Each thread polls its own assigned partitions and writes its own poll independently through
 * the stateless {@link BatchRecordDispatcher}; there is no shared accumulator, so fetch and
 * write overlap across threads and the work scales {@code N}-way with no cross-thread lock.
 *
 * <h2>Offset-after-write</h2>
 * <p>The container runs in {@link
 * org.springframework.kafka.listener.ContainerProperties.AckMode#MANUAL manual-ack} mode.
 * {@link #onBatch(List, Acknowledgment)} acknowledges the poll batch — committing every offset
 * up to the highest consumed in the batch — only after the dispatcher's store writes have
 * returned normally. If any decode or write throws, the method does not acknowledge and lets
 * the exception propagate; the offsets stay uncommitted and Kafka re-delivers the batch on the
 * next poll or after a rebalance. Combined with the {@link
 * it.lpworks.jbmp.consumer.store.StoreWriter}'s all-or-nothing, idempotent contract this gives
 * at-least-once delivery with zero data loss.
 *
 * <p>This class is intentionally thin: all decode and routing logic lives in {@link
 * BatchRecordDispatcher}, which is unit tested without Kafka. The end-to-end listener path is
 * exercised by an {@code @Tag("integration")} embedded-broker test.
 */
@Component
public class KafkaIngestService {

    private final BatchRecordDispatcher dispatcher;

    /**
     * Creates the ingest service.
     *
     * @param dispatcher the stateless per-poll decode-and-write core (never {@code null})
     * @throws NullPointerException if {@code dispatcher} is {@code null}
     */
    public KafkaIngestService(BatchRecordDispatcher dispatcher) {
        this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
    }

    /**
     * Consumes one poll batch of the high-volume route-monitor topics, persists it, and commits
     * its offsets. Runs on the route-monitor container's threads only, so a poll here is always a
     * pure bulk {@code COPY} + RIB projection. On a clean return the batch is acknowledged
     * (offset-after-write); a decode or store failure propagates so the offsets are not committed
     * and Kafka re-delivers the records.
     *
     * @param records the raw Kafka records of a single poll (never {@code null}; may be empty)
     * @param ack     the batch acknowledgement used as the offset commit token
     */
    @KafkaListener(
            topics = {
                    "${jbmp.consumer.topics.route-monitor-v4:jbmp.route-monitor.v4}",
                    "${jbmp.consumer.topics.route-monitor-v6:jbmp.route-monitor.v6}"
            },
            containerFactory = "byteArrayKafkaListenerContainerFactory")
    public void onRouteMonitorBatch(List<ConsumerRecord<byte[], byte[]>> records,
            Acknowledgment ack) {
        dispatcher.writeBatch(records);
        ack.acknowledge();
    }

    /**
     * Consumes one poll batch of the lower-volume peer-event, stats and route-mirror topics on a
     * small, separate thread pool. Isolating these topics from {@link
     * #onRouteMonitorBatch(List, Acknowledgment)} keeps their per-message/batched writes off the
     * route-monitor {@code COPY} threads, so a burst of statistics reports cannot stall the
     * historical bulk-load path. Same offset-after-write contract.
     *
     * @param records the raw Kafka records of a single poll (never {@code null}; may be empty)
     * @param ack     the batch acknowledgement used as the offset commit token
     */
    @KafkaListener(
            topics = {
                    "${jbmp.consumer.topics.peer-events:jbmp.peer-events}",
                    "${jbmp.consumer.topics.stats:jbmp.stats}",
                    "${jbmp.consumer.topics.route-mirror:jbmp.route-mirror}"
            },
            containerFactory = "byteArrayKafkaListenerContainerFactory",
            concurrency = "${jbmp.consumer.aux-concurrency:3}")
    public void onAuxBatch(List<ConsumerRecord<byte[], byte[]>> records, Acknowledgment ack) {
        dispatcher.writeBatch(records);
        ack.acknowledge();
    }
}
