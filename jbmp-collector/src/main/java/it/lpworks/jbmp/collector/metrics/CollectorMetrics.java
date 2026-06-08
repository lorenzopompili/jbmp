package it.lpworks.jbmp.collector.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

/**
 * Micrometer instrumentation for the collector's TCP, parsing and publishing pipeline.
 *
 * <p>The counters are organised so that downstream dashboards and alerts can be built
 * directly from the Prometheus scrape:
 * <ul>
 *   <li>{@code jbmp.collector.connections.opened} / {@code .closed} — router-session
 *       lifecycle, plus {@code .rejected} for connections refused once {@code maxRouters}
 *       is reached;</li>
 *   <li>{@code jbmp.collector.messages.parsed} tagged by BMP message {@code type};</li>
 *   <li>{@code jbmp.collector.messages.published} tagged by destination {@code topic};</li>
 *   <li>{@code jbmp.collector.parse.errors} — per-message decode/enrich failures that are
 *       absorbed without dropping the connection;</li>
 *   <li>{@code jbmp.collector.publish.errors} tagged by {@code topic} — Kafka send failures
 *       that are absorbed without disturbing the read loop.</li>
 * </ul>
 *
 * <p>Tagged counters are resolved lazily through the registry, which caches them, so the
 * same {@code (name, tags)} pair always maps to a single underlying meter.
 */
@Component
public class CollectorMetrics {

    private static final String CONNECTIONS_OPENED = "jbmp.collector.connections.opened";
    private static final String CONNECTIONS_CLOSED = "jbmp.collector.connections.closed";
    private static final String CONNECTIONS_REJECTED = "jbmp.collector.connections.rejected";
    private static final String MESSAGES_PARSED = "jbmp.collector.messages.parsed";
    private static final String MESSAGES_PUBLISHED = "jbmp.collector.messages.published";
    private static final String PARSE_ERRORS = "jbmp.collector.parse.errors";
    private static final String PUBLISH_ERRORS = "jbmp.collector.publish.errors";

    private static final String TAG_TYPE = "type";
    private static final String TAG_TOPIC = "topic";

    private final MeterRegistry registry;
    private final Counter connectionsOpened;
    private final Counter connectionsClosed;
    private final Counter connectionsRejected;
    private final Counter parseErrors;

    /**
     * Creates the metric set, eagerly registering the untagged counters.
     *
     * @param registry the Micrometer registry the counters are published through (never
     *                 {@code null})
     */
    public CollectorMetrics(MeterRegistry registry) {
        this.registry = registry;
        this.connectionsOpened = Counter.builder(CONNECTIONS_OPENED)
                .description("Router TCP connections accepted")
                .register(registry);
        this.connectionsClosed = Counter.builder(CONNECTIONS_CLOSED)
                .description("Router TCP connections closed")
                .register(registry);
        this.connectionsRejected = Counter.builder(CONNECTIONS_REJECTED)
                .description("Router TCP connections rejected because maxRouters was reached")
                .register(registry);
        this.parseErrors = Counter.builder(PARSE_ERRORS)
                .description("Per-message BMP/BGP parse or enrichment failures absorbed by the read loop")
                .register(registry);
    }

    /** Records that a router TCP connection was accepted. */
    public void connectionOpened() {
        connectionsOpened.increment();
    }

    /** Records that a router TCP connection was closed. */
    public void connectionClosed() {
        connectionsClosed.increment();
    }

    /** Records that a router TCP connection was rejected because the router cap was reached. */
    public void connectionRejected() {
        connectionsRejected.increment();
    }

    /**
     * Records that one BMP message of the given type was successfully parsed.
     *
     * @param type the BMP message type tag (for example {@code ROUTE_MONITORING})
     */
    public void messageParsed(String type) {
        registry.counter(MESSAGES_PARSED, TAG_TYPE, type).increment();
    }

    /**
     * Records that one enriched message was published to the given topic.
     *
     * @param topic the destination Kafka topic name
     */
    public void messagePublished(String topic) {
        registry.counter(MESSAGES_PUBLISHED, TAG_TOPIC, topic).increment();
    }

    /** Records a per-message parse or enrichment failure. */
    public void parseError() {
        parseErrors.increment();
    }

    /**
     * Records a Kafka publish failure for the given topic.
     *
     * @param topic the destination Kafka topic name the send failed for
     */
    public void publishError(String topic) {
        registry.counter(PUBLISH_ERRORS, TAG_TOPIC, topic).increment();
    }
}
