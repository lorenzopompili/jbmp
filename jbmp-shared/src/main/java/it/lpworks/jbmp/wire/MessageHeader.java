package it.lpworks.jbmp.wire;

import java.util.Objects;
import java.util.UUID;

/**
 * The common provenance header carried by every enriched message exchanged over Kafka.
 *
 * <p>It records when the underlying event occurred and was observed, which collector
 * processed it, and the deterministic identities (see
 * {@link it.lpworks.jbmp.identity.UuidFactory}) of the router and monitored peer that
 * produced it. BMP timestamps originate from the Per-Peer Header (RFC 7854, Section 4.2);
 * the receive timestamp is assigned locally by the collector.
 *
 * @param timestampNanos  the event time in nanoseconds since the Unix epoch, derived from
 *                        the BMP Per-Peer Header timestamp (RFC 7854 §4.2)
 * @param receivedAtNanos the local receive time in nanoseconds since the Unix epoch
 * @param collectorId     the identifier of the collector instance that produced this message
 * @param routerId        the deterministic identity of the monitored router (never {@code null})
 * @param peerId          the deterministic identity of the monitored BGP peer (never {@code null})
 */
public record MessageHeader(
        long timestampNanos,
        long receivedAtNanos,
        int collectorId,
        UUID routerId,
        UUID peerId) {

    /**
     * Validates that both identities are present.
     *
     * @throws NullPointerException if {@code routerId} or {@code peerId} is {@code null}
     */
    public MessageHeader {
        Objects.requireNonNull(routerId, "routerId");
        Objects.requireNonNull(peerId, "peerId");
    }
}
