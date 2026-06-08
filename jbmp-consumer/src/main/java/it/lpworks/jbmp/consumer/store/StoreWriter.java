package it.lpworks.jbmp.consumer.store;

import java.util.List;

import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;

/**
 * The persistence service-provider interface for the jBMP consumer.
 *
 * <p>A {@code StoreWriter} is the sink to which decoded, enriched messages are written. The
 * batching engine drives it; the Kafka wiring commits offsets only after a write returns
 * normally. The contract that makes the offset-after-write guarantee possible is therefore
 * <em>all-or-nothing</em>: every method must either fully persist its argument(s) or throw,
 * so that the caller can safely withhold the offset commit and let Kafka re-deliver the
 * batch on the next poll or rebalance.
 *
 * <h2>Idempotency and at-least-once delivery</h2>
 * <p>Because offsets are committed after the write, a crash between the durable write and
 * the commit causes the same records to be re-delivered. Implementations must therefore be
 * able to absorb duplicates without corrupting state. The historical
 * {@linkplain #writeRouteMonitorBatch(List) route-monitor append} is naturally
 * duplicate-tolerant (a re-inserted historical row is at worst a harmless repeat), while the
 * current-state {@linkplain #applyRibState(List) RIB projection} is an explicit idempotent
 * upsert/delete so that re-applying a batch converges to the same routing state.
 *
 * @see InMemoryStoreWriter
 */
public interface StoreWriter {

    /**
     * Appends a batch of route-monitoring events to the historical store as a single
     * all-or-nothing unit.
     *
     * <p>This is the high-volume path: implementations are expected to use a bulk/copy
     * mechanism rather than per-row statements. The list preserves the order in which the
     * events were consumed.
     *
     * @param batch the route-monitoring events to append (never {@code null}; may be empty,
     *              in which case the call is a no-op)
     * @throws RuntimeException if the batch could not be fully persisted; in that case the
     *                          caller must not commit the corresponding offsets
     */
    void writeRouteMonitorBatch(List<RouteMonitorMessage> batch);

    /**
     * Appends a batch of route-monitoring events together with each row's Kafka provenance
     * (the source partition and offset, indexed in lock-step with {@code batch}). The default
     * ignores the provenance and delegates to {@link #writeRouteMonitorBatch(List)}; a
     * database-backed implementation overrides it to stamp the {@code kafka_partition} /
     * {@code kafka_offset} columns.
     *
     * @param batch      the route-monitoring events (never {@code null}; may be empty)
     * @param partitions the source Kafka partition per entry of {@code batch}
     * @param offsets    the source Kafka offset per entry of {@code batch}
     */
    default void writeRouteMonitorBatch(List<RouteMonitorMessage> batch, int[] partitions,
            long[] offsets) {
        writeRouteMonitorBatch(batch);
    }

    /**
     * Projects a batch of route-monitoring events onto the current routing-state view.
     *
     * <p>The projection is keyed by {@link RibKey} (peer + prefix + optional Path
     * Identifier): an {@linkplain it.lpworks.jbmp.wire.RouteAction#ANNOUNCE announce}
     * upserts the entry, a {@linkplain it.lpworks.jbmp.wire.RouteAction#WITHDRAW withdraw}
     * removes it. End-of-RIB markers carry no NLRI and do not alter state. The operation is
     * idempotent: re-applying the same batch yields the same final state, which keeps the
     * view correct under at-least-once re-delivery.
     *
     * @param batch the route-monitoring events to apply, in consumption order (never
     *              {@code null}; may be empty, in which case the call is a no-op)
     * @throws RuntimeException if the state could not be fully updated; in that case the
     *                          caller must not commit the corresponding offsets
     */
    void applyRibState(List<RouteMonitorMessage> batch);

    /**
     * Persists a single peering-session lifecycle event.
     *
     * @param event the peer up/down event (never {@code null})
     * @throws RuntimeException if the event could not be persisted
     */
    void writePeerEvent(PeerEventMessage event);

    /**
     * Persists a single statistics snapshot.
     *
     * @param stats the statistics report (never {@code null})
     * @throws RuntimeException if the report could not be persisted
     */
    void writeStats(StatsReportMessage stats);

    /**
     * Persists a single route-mirroring event.
     *
     * @param mirror the route-mirroring event (never {@code null})
     * @throws RuntimeException if the event could not be persisted
     */
    void writeRouteMirror(RouteMirrorMessage mirror);

    /**
     * Persists a batch of peering-session lifecycle events as a single unit.
     *
     * <p>The default writes each event individually. Implementations backed by a remote
     * database should override this to write the whole batch in one round trip: a burst of
     * peer events — many sessions coming up during an initial dump, or a flap storm — would
     * otherwise pay one transaction per event and serialise the consumer thread that owns the
     * peer-event partition.
     *
     * @param events the peer events in consumption order (never {@code null}; may be empty,
     *               in which case the call is a no-op)
     * @throws RuntimeException if the batch could not be fully persisted
     */
    default void writePeerEvents(List<PeerEventMessage> events) {
        events.forEach(this::writePeerEvent);
    }

    /**
     * Persists a batch of statistics snapshots as a single unit. The default writes each report
     * individually; remote-database implementations should override it to batch the writes for
     * the same reason as {@link #writePeerEvents(List)}.
     *
     * @param reports the statistics reports in consumption order (never {@code null}; may be
     *               empty, in which case the call is a no-op)
     * @throws RuntimeException if the batch could not be fully persisted
     */
    default void writeStatsBatch(List<StatsReportMessage> reports) {
        reports.forEach(this::writeStats);
    }

    /**
     * Persists a batch of route-mirroring events as a single unit. The default writes each event
     * individually; remote-database implementations should override it to batch the writes for
     * the same reason as {@link #writePeerEvents(List)}.
     *
     * @param mirrors the route-mirroring events in consumption order (never {@code null}; may be
     *               empty, in which case the call is a no-op)
     * @throws RuntimeException if the batch could not be fully persisted
     */
    default void writeRouteMirrors(List<RouteMirrorMessage> mirrors) {
        mirrors.forEach(this::writeRouteMirror);
    }
}
