package it.lpworks.jbmp.collector.publish;

import java.util.UUID;

import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;

/**
 * The publication SPI for enriched BMP messages produced by the collector.
 *
 * <p>The enrichment stage converts each parsed BMP message into one or more of the wire DTOs
 * in {@link it.lpworks.jbmp.wire}; this interface is the sink those DTOs are handed to. The
 * production implementation ({@link KafkaBmpMessagePublisher}) encodes each DTO with
 * {@link it.lpworks.jbmp.wire.WireCodec} and produces it to the appropriate Kafka topic,
 * keyed by the 16-byte router identity so that all traffic from a single router lands on one
 * partition and therefore preserves per-router ordering.
 *
 * <h2>Failure policy</h2>
 * <p>Implementations <strong>must not</strong> propagate transport failures into the caller:
 * a failed publish is to be recorded (metric + log) and swallowed so that a transient Kafka
 * problem never tears down an otherwise healthy router session. Methods may still throw for
 * programming errors such as a {@code null} argument.
 */
public interface BmpMessagePublisher {

    /**
     * Publishes one enriched, single-prefix route-monitoring event.
     *
     * @param message the message to publish (never {@code null})
     */
    void publishRouteMonitor(RouteMonitorMessage message);

    /**
     * Publishes one enriched peering-session lifecycle event.
     *
     * @param message the message to publish (never {@code null})
     */
    void publishPeerEvent(PeerEventMessage message);

    /**
     * Publishes one enriched statistics snapshot.
     *
     * @param message the message to publish (never {@code null})
     */
    void publishStats(StatsReportMessage message);

    /**
     * Publishes one enriched route-mirroring event.
     *
     * @param message the message to publish (never {@code null})
     */
    void publishRouteMirror(RouteMirrorMessage message);

    /**
     * Publishes the verbatim bytes of a single BMP message for archival and reprocessing.
     *
     * @param routerId       the deterministic router identity used as the partition key
     *                       (never {@code null})
     * @param rawBmpMessage  the complete, framed BMP message bytes (never {@code null})
     */
    void publishRaw(UUID routerId, byte[] rawBmpMessage);
}
