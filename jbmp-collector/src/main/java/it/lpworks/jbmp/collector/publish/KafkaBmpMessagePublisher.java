package it.lpworks.jbmp.collector.publish;

import java.util.Objects;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import it.lpworks.jbmp.collector.config.CollectorProperties;
import it.lpworks.jbmp.collector.metrics.CollectorMetrics;
import it.lpworks.jbmp.wire.MessageHeader;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;
import it.lpworks.jbmp.wire.WireCodec;

/**
 * The Kafka-backed {@link BmpMessagePublisher}.
 *
 * <p>Each enriched DTO is encoded with {@link WireCodec} and produced to a topic chosen by
 * its type (route-monitor traffic is split IPv4/IPv6 by {@link RouteMonitorMessage#ipv4()}).
 * The record <strong>key is the 16-byte router identity</strong> derived from the message
 * header, so the default partitioner hashes all traffic from one router onto a single
 * partition, giving per-router ordering of route, peer and stats events. The raw-bytes topic
 * is keyed the same way for the same reason.
 *
 * <h2>Failure isolation</h2>
 * <p>A send returns a {@link java.util.concurrent.CompletableFuture}; an asynchronous broker
 * failure is recorded via {@link CollectorMetrics#publishError(String)} and logged from a
 * completion callback, and a synchronous failure (for example an encode error or a producer
 * that rejects the record outright) is caught and recorded the same way. Neither path ever
 * throws back into the collector's read loop, satisfying the SPI's failure-policy contract.
 *
 * <p>The bean is active by default and can be disabled with
 * {@code jbmp.collector.kafka.enabled=false} (for example to substitute a different publisher
 * in a non-Kafka deployment).
 */
@Component
@ConditionalOnProperty(prefix = "jbmp.collector.kafka", name = "enabled",
        havingValue = "true", matchIfMissing = true)
public class KafkaBmpMessagePublisher implements BmpMessagePublisher {

    private static final Logger log = LoggerFactory.getLogger(KafkaBmpMessagePublisher.class);

    private final KafkaTemplate<byte[], byte[]> kafkaTemplate;
    private final CollectorProperties.Topics topics;
    private final CollectorMetrics metrics;

    /**
     * Creates the publisher.
     *
     * @param kafkaTemplate the byte-array Kafka template (never {@code null})
     * @param properties    the bound collector properties supplying the topic names (never
     *                      {@code null})
     * @param metrics       the metric set for publish counters (never {@code null})
     */
    public KafkaBmpMessagePublisher(KafkaTemplate<byte[], byte[]> kafkaTemplate,
                                    CollectorProperties properties,
                                    CollectorMetrics metrics) {
        this.kafkaTemplate = Objects.requireNonNull(kafkaTemplate, "kafkaTemplate");
        this.topics = Objects.requireNonNull(properties, "properties").topics();
        this.metrics = Objects.requireNonNull(metrics, "metrics");
    }

    @Override
    public void publishRouteMonitor(RouteMonitorMessage message) {
        Objects.requireNonNull(message, "message");
        String topic = message.ipv4() ? topics.routeMonitorV4() : topics.routeMonitorV6();
        publish(topic, routerKey(message.header()), () -> WireCodec.encodeRouteMonitor(message));
    }

    @Override
    public void publishPeerEvent(PeerEventMessage message) {
        Objects.requireNonNull(message, "message");
        publish(topics.peerEvents(), routerKey(message.header()),
                () -> WireCodec.encodePeerEvent(message));
    }

    @Override
    public void publishStats(StatsReportMessage message) {
        Objects.requireNonNull(message, "message");
        publish(topics.stats(), routerKey(message.header()),
                () -> WireCodec.encodeStatsReport(message));
    }

    @Override
    public void publishRouteMirror(RouteMirrorMessage message) {
        Objects.requireNonNull(message, "message");
        publish(topics.routeMirror(), routerKey(message.header()),
                () -> WireCodec.encodeRouteMirror(message));
    }

    @Override
    public void publishRaw(UUID routerId, byte[] rawBmpMessage) {
        Objects.requireNonNull(routerId, "routerId");
        Objects.requireNonNull(rawBmpMessage, "rawBmpMessage");
        publish(topics.raw(), uuidToBytes(routerId), () -> rawBmpMessage);
    }

    /**
     * Encodes and sends one record, isolating every failure mode from the caller.
     *
     * <p>The value is produced lazily so that an encode failure is caught here rather than at
     * the call site. A synchronous send failure and an asynchronous broker failure are both
     * funnelled to {@link #recordFailure(String, Throwable)}.
     *
     * @param topic    the destination topic
     * @param key      the partition key (the 16-byte router identity)
     * @param encoder  supplies the encoded value bytes
     */
    private void publish(String topic, byte[] key, java.util.function.Supplier<byte[]> encoder) {
        try {
            byte[] value = encoder.get();
            kafkaTemplate.send(topic, key, value).whenComplete((result, ex) -> {
                if (ex != null) {
                    recordFailure(topic, ex);
                } else {
                    metrics.messagePublished(topic);
                }
            });
        } catch (RuntimeException e) {
            // Encode failure or a producer that rejects the record synchronously: never let
            // it escape into the read loop.
            recordFailure(topic, e);
        }
    }

    /**
     * Records and logs a publish failure for the given topic without rethrowing.
     *
     * @param topic the topic the send failed for
     * @param ex    the failure cause
     */
    private void recordFailure(String topic, Throwable ex) {
        metrics.publishError(topic);
        log.warn("Failed to publish message to topic {}: {}", topic, ex.toString());
        if (log.isDebugEnabled()) {
            log.debug("Publish failure detail for topic {}", topic, ex);
        }
    }

    /**
     * Extracts the 16-byte partition key from a message header's router identity.
     *
     * @param header the provenance header
     * @return the router UUID as 16 big-endian bytes
     */
    private static byte[] routerKey(MessageHeader header) {
        return uuidToBytes(header.routerId());
    }

    /**
     * Encodes a UUID as 16 bytes: most-significant 64 bits then least-significant 64 bits
     * (RFC 4122 big-endian layout, matching {@link WireCodec}'s UUID encoding).
     *
     * @param uuid the UUID to encode
     * @return the 16-byte representation
     */
    private static byte[] uuidToBytes(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (msb >>> (56 - 8 * i));
            out[8 + i] = (byte) (lsb >>> (56 - 8 * i));
        }
        return out;
    }
}
