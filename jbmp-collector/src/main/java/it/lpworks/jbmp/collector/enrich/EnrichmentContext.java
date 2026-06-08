package it.lpworks.jbmp.collector.enrich;

import java.util.Objects;
import java.util.function.LongSupplier;

import it.lpworks.jbmp.identity.UuidFactory;

/**
 * Per-connection context supplied to the {@link BmpEnricher} for every message parsed on one
 * router session.
 *
 * <p>It carries the inputs the enricher cannot derive from the BMP message itself: the
 * <em>router key</em> from which the deterministic router identity is computed, the configured
 * collector identifier stamped into every provenance header, and a supplier of the local
 * receive timestamp. The receive timestamp is supplied as a {@link LongSupplier} so it can be
 * sampled at enrichment time (typically {@code System.currentTimeMillis() * 1_000_000}) and so
 * tests can inject a deterministic clock.
 *
 * <h2>Router key and identity</h2>
 * <p>A router's identity is {@link UuidFactory#router(byte[])} applied to the router key, which
 * is the router's TCP source IP address bytes. This matches the reference collector's IP-based
 * router identity, so a router resolves to the same identity — and the same Kafka partition — in
 * both systems. The key is fixed for the lifetime of the connection.
 *
 * <h2>Thread-safety</h2>
 * <p>One context belongs to exactly one router session and is read only on that session's single
 * (virtual) thread; the router key is immutable.
 */
public final class EnrichmentContext {

    private final int collectorId;
    private final LongSupplier receivedAtNanos;

    /** The per-connection router key (the TCP source IP bytes); fixed for the connection. */
    private final byte[] routerKey;

    /**
     * Creates a context whose router key defaults to the supplied bytes (the TCP source IP).
     *
     * @param routerKey       the initial router key bytes (the TCP source IP, 4 or 16 octets);
     *                        defensively copied
     * @param collectorId     the collector instance identifier for the provenance header
     * @param receivedAtNanos supplies the local receive time in nanoseconds since the Unix epoch
     * @throws NullPointerException     if {@code routerKey} or {@code receivedAtNanos} is
     *                                  {@code null}
     * @throws IllegalArgumentException if {@code routerKey} is empty
     */
    public EnrichmentContext(byte[] routerKey, int collectorId, LongSupplier receivedAtNanos) {
        Objects.requireNonNull(routerKey, "routerKey");
        Objects.requireNonNull(receivedAtNanos, "receivedAtNanos");
        if (routerKey.length == 0) {
            throw new IllegalArgumentException("routerKey must not be empty");
        }
        this.routerKey = routerKey.clone();
        this.collectorId = collectorId;
        this.receivedAtNanos = receivedAtNanos;
    }

    /**
     * Returns a defensive copy of the current router key bytes.
     *
     * @return a fresh copy of the router key
     */
    public byte[] routerKey() {
        return routerKey.clone();
    }

    /**
     * Returns the collector instance identifier stamped into every provenance header.
     *
     * @return the collector id
     */
    public int collectorId() {
        return collectorId;
    }

    /**
     * Returns the supplier of the local receive timestamp in nanoseconds since the Unix epoch.
     *
     * @return the receive-time supplier
     */
    public LongSupplier receivedAtNanos() {
        return receivedAtNanos;
    }
}
