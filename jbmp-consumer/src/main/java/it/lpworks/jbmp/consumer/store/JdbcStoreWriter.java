package it.lpworks.jbmp.consumer.store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.postgresql.PGConnection;
import org.postgresql.copy.CopyManager;

import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteAction;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;

/**
 * A PostgreSQL-backed {@link StoreWriter}.
 *
 * <p>The high-volume historical path ({@link #writeRouteMonitorBatch(List)}) uses the
 * PostgreSQL {@code COPY} bulk-load protocol via {@link CopyManager} obtained from the
 * unwrapped {@link PGConnection}; this is dramatically faster than per-row {@code INSERT}s for
 * large batches. The batch is rendered by {@link RouteMonitorCopy} into the binary {@code COPY}
 * stream carrying the full BGP attribute set (AS_PATH and segments, standard/large/extended
 * communities, aggregator, route-reflector attributes, route targets, and the opaque
 * EVPN/FlowSpec/SR-Policy/BGP-LS families). The current-state projection
 * ({@link #applyRibState(List)}) uses {@code INSERT ... ON CONFLICT ... DO UPDATE} for announces
 * and {@code DELETE} for withdraws, both keyed by the {@link RibKey} tuple, making the operation
 * idempotent under at-least-once re-delivery. The three low-volume single-message methods use
 * ordinary prepared statements.
 *
 * <p>The two high-volume paths run on an <em>auto-commit</em> connection, which the profiler
 * showed roughly halves the network round trips to the (remote) database — the dominant cost of
 * the consumer. {@link #writeRouteMonitorBatch(List)} is a single {@code COPY}, which is atomic
 * on its own, so its commit is implicit and no separate {@code COMMIT} round trip is spent; the
 * call still returns only once the rows are durable, preserving the offset-after-write guarantee.
 * {@link #applyRibState(List)} is an idempotent, fully rebuildable projection, so it likewise
 * needs no surrounding transaction. The three low-volume single-message writers keep an explicit
 * transaction (their per-poll volume is negligible, so the extra round trip is irrelevant).
 *
 * <p>Binary network values (prefixes, next hops, BGP identifiers, OPEN/mirrored PDUs) are
 * stored as {@code bytea}: on the binary route-monitor path their raw bytes are written
 * verbatim, while the prepared-statement paths bind them directly as JDBC byte parameters.
 */
public final class JdbcStoreWriter implements StoreWriter {

    /** {@code COPY} target: column order must match {@link RouteMonitorCopy#COLUMN_LIST}. */
    private static final String COPY_ROUTE_MONITOR_SQL =
            "COPY route_monitor (" + RouteMonitorCopy.COLUMN_LIST + ") FROM STDIN WITH (FORMAT binary)";

    private static final String UPSERT_RIB_SQL = """
            INSERT INTO rib_state (
                peer_id, prefix, router_id, origin_as, as_path, next_hop, med, local_pref, origin,
                communities, large_communities, ext_communities, vprn_id, route_target,
                is_ipv4, is_prepolicy, peer_rd, path_id, timestamp, updated_at
            ) VALUES (?, ?::cidr, ?, ?, ?, ?::inet, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now())
            ON CONFLICT (peer_id, prefix) DO UPDATE SET
                router_id = EXCLUDED.router_id, origin_as = EXCLUDED.origin_as,
                as_path = EXCLUDED.as_path, next_hop = EXCLUDED.next_hop, med = EXCLUDED.med,
                local_pref = EXCLUDED.local_pref, origin = EXCLUDED.origin,
                communities = EXCLUDED.communities, large_communities = EXCLUDED.large_communities,
                ext_communities = EXCLUDED.ext_communities, vprn_id = EXCLUDED.vprn_id,
                route_target = EXCLUDED.route_target, is_ipv4 = EXCLUDED.is_ipv4,
                is_prepolicy = EXCLUDED.is_prepolicy, peer_rd = EXCLUDED.peer_rd,
                path_id = EXCLUDED.path_id, timestamp = EXCLUDED.timestamp, updated_at = now()
            """;

    private static final String DELETE_RIB_SQL =
            "DELETE FROM rib_state WHERE peer_id = ? AND prefix = ?::cidr";

    private static final String INSERT_PEER_EVENT_SQL = """
            INSERT INTO peer_events (
                event_time, received_at, collector_id, router_id, peer_id,
                event_type, remote_ip, remote_asn, remote_bgp_id, local_ip, local_asn,
                local_bgp_id, remote_port, local_port, peer_rd,
                bmp_reason, bgp_error_code, bgp_error_subcode, error_text,
                sent_open, received_open, info_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String INSERT_STATS_SQL = """
            INSERT INTO bmp_stats (
                event_time, received_at, collector_id, router_id, peer_id, stat_type, stat_value
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """;

    private static final String INSERT_ROUTE_MIRROR_SQL = """
            INSERT INTO route_mirror (
                event_time, received_at, collector_id, router_id, peer_id,
                information_code, mirrored_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """;

    private final DataSource dataSource;

    /**
     * Creates a writer over the given {@link DataSource}.
     *
     * @param dataSource the PostgreSQL data source (never {@code null})
     */
    public JdbcStoreWriter(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public void writeRouteMonitorBatch(List<RouteMonitorMessage> batch) {
        writeRouteMonitorBatch(batch, null, null);
    }

    @Override
    public void writeRouteMonitorBatch(List<RouteMonitorMessage> batch, int[] partitions,
            long[] offsets) {
        if (batch.isEmpty()) {
            return;
        }
        // Render the batch into the PostgreSQL binary COPY format, which the server ingests far
        // faster than the text format because it skips per-value text parsing. End-of-RIB markers
        // are filtered inside the encoder; the resulting payload always carries the header and
        // trailer, so an all-marker batch is a harmless zero-row load rather than an error. The
        // Kafka partition/offset, when supplied, are stamped into the provenance columns.
        byte[] payload = RouteMonitorCopy.encode(batch, partitions, offsets);
        // A single COPY is atomic by itself: on an auto-commit connection it commits implicitly
        // when the server returns the row count, so no extra COMMIT round trip is spent and the
        // call still returns only once every row is durable.
        inAutoCommit(connection -> {
            CopyManager copyManager = connection.unwrap(PGConnection.class).getCopyAPI();
            try (InputStream in = new ByteArrayInputStream(payload)) {
                copyManager.copyIn(COPY_ROUTE_MONITOR_SQL, in);
            } catch (IOException e) {
                throw new SQLException("Failed to stream route-monitor COPY payload", e);
            }
        });
    }

    @Override
    public void applyRibState(List<RouteMonitorMessage> batch) {
        if (batch.isEmpty()) {
            return;
        }
        // Collapse the poll batch to the last write per key before touching the database. Within
        // a partition the records arrive in offset order and every record for a given key lands
        // on one partition, so the final occurrence is the current state. This is required for
        // correctness once batched inserts are rewritten into a single multi-row statement:
        // PostgreSQL rejects an "INSERT ... ON CONFLICT DO UPDATE" that proposes the same
        // conflict key twice ("cannot affect row a second time"), which a re-advertised prefix in
        // the same poll would otherwise trigger. It also cuts the number of upserts when a prefix
        // churns within one poll. Last-write-wins is order-preserving via the linked map.
        Map<RibKey, RouteMonitorMessage> latest = new LinkedHashMap<>(batch.size() * 2);
        for (RouteMonitorMessage msg : batch) {
            if (msg.endOfRib()) {
                continue;
            }
            latest.put(RibKey.of(msg), msg);
        }
        if (latest.isEmpty()) {
            return;
        }
        // The projection is idempotent and fully rebuildable from the route_monitor history, so
        // it runs on an auto-commit connection (no surrounding transaction, no COMMIT round trip)
        // off the consumer's offset-commit path.
        inAutoCommit(connection -> {
            try (PreparedStatement upsert = connection.prepareStatement(UPSERT_RIB_SQL);
                    PreparedStatement delete = connection.prepareStatement(DELETE_RIB_SQL)) {
                int upserts = 0;
                int deletes = 0;
                for (Map.Entry<RibKey, RouteMonitorMessage> entry : latest.entrySet()) {
                    RibKey key = entry.getKey();
                    RouteMonitorMessage msg = entry.getValue();
                    if (msg.action() == RouteAction.WITHDRAW) {
                        delete.setObject(1, key.peerId());
                        delete.setString(2, PgText.cidr(key.prefix(), key.prefixLength(),
                                msg.ipv4()));
                        delete.addBatch();
                        deletes++;
                    } else {
                        bindRibUpsert(connection, upsert, msg, key);
                        upsert.addBatch();
                        upserts++;
                    }
                }
                // Skip the empty executeBatch round trips: an all-announce batch never deletes,
                // which is the common case during the initial table dump.
                if (upserts > 0) {
                    upsert.executeBatch();
                }
                if (deletes > 0) {
                    delete.executeBatch();
                }
            }
        });
    }

    @Override
    public void writePeerEvent(PeerEventMessage event) {
        writePeerEvents(List.of(event));
    }

    @Override
    public void writePeerEvents(List<PeerEventMessage> events) {
        if (events.isEmpty()) {
            return;
        }
        // One transaction for the whole poll's peer events, not one per event: a dump that
        // brings up hundreds of peers at once would otherwise pay a round trip per row and
        // serialise the consumer thread that owns the peer-event partition.
        inTransaction(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(INSERT_PEER_EVENT_SQL)) {
                for (PeerEventMessage event : events) {
                    bindPeerEvent(ps, event);
                    ps.addBatch();
                }
                ps.executeBatch();
            }
        });
    }

    @Override
    public void writeStats(StatsReportMessage stats) {
        writeStatsBatch(List.of(stats));
    }

    @Override
    public void writeStatsBatch(List<StatsReportMessage> reports) {
        if (reports.isEmpty()) {
            return;
        }
        // One transaction for every counter of every report in the poll. Statistics reports are
        // periodic but arrive in bursts (every peer reports on the same tick), so per-report
        // transactions are the dominant serial cost on the stats partition's thread under load.
        inTransaction(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(INSERT_STATS_SQL)) {
                for (StatsReportMessage report : reports) {
                    for (var entry : report.counters().entrySet()) {
                        int i = 1;
                        ps.setObject(i++, PgText.ts(report.header().timestampNanos()));
                        ps.setObject(i++, PgText.ts(report.header().receivedAtNanos()));
                        ps.setLong(i++, Integer.toUnsignedLong(report.header().collectorId()));
                        ps.setObject(i++, report.header().routerId());
                        ps.setObject(i++, report.header().peerId());
                        ps.setInt(i++, entry.getKey());
                        ps.setLong(i, entry.getValue());
                        ps.addBatch();
                    }
                }
                ps.executeBatch();
            }
        });
    }

    @Override
    public void writeRouteMirror(RouteMirrorMessage mirror) {
        writeRouteMirrors(List.of(mirror));
    }

    @Override
    public void writeRouteMirrors(List<RouteMirrorMessage> mirrors) {
        if (mirrors.isEmpty()) {
            return;
        }
        inTransaction(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(INSERT_ROUTE_MIRROR_SQL)) {
                for (RouteMirrorMessage mirror : mirrors) {
                    bindRouteMirror(ps, mirror);
                    ps.addBatch();
                }
                ps.executeBatch();
            }
        });
    }

    private void bindPeerEvent(PreparedStatement ps, PeerEventMessage event) throws SQLException {
        int i = 1;
        ps.setObject(i++, PgText.ts(event.header().timestampNanos()));
        ps.setObject(i++, PgText.ts(event.header().receivedAtNanos()));
        ps.setLong(i++, Integer.toUnsignedLong(event.header().collectorId()));
        ps.setObject(i++, event.header().routerId());
        ps.setObject(i++, event.header().peerId());
        ps.setString(i++, event.eventType().name());
        ps.setBytes(i++, nullIfEmpty(event.remoteIp()));
        ps.setLong(i++, event.remoteAsn());
        ps.setBytes(i++, nullIfEmpty(event.remoteBgpId()));
        ps.setBytes(i++, nullIfEmpty(event.localIp()));
        ps.setLong(i++, event.localAsn());
        ps.setBytes(i++, nullIfEmpty(event.localBgpId()));
        ps.setInt(i++, event.remotePort());
        ps.setInt(i++, event.localPort());
        ps.setString(i++, event.peerRd());
        ps.setInt(i++, event.bmpReason());
        ps.setInt(i++, event.bgpErrorCode());
        ps.setInt(i++, event.bgpErrorSubcode());
        ps.setString(i++, event.errorText());
        ps.setBytes(i++, nullIfEmpty(event.sentOpen()));
        ps.setBytes(i++, nullIfEmpty(event.receivedOpen()));
        ps.setString(i, event.infoData());
    }

    private void bindRouteMirror(PreparedStatement ps, RouteMirrorMessage mirror)
            throws SQLException {
        int i = 1;
        ps.setObject(i++, PgText.ts(mirror.header().timestampNanos()));
        ps.setObject(i++, PgText.ts(mirror.header().receivedAtNanos()));
        ps.setLong(i++, Integer.toUnsignedLong(mirror.header().collectorId()));
        ps.setObject(i++, mirror.header().routerId());
        ps.setObject(i++, mirror.header().peerId());
        if (mirror.informationCode().isPresent()) {
            ps.setInt(i++, mirror.informationCode().getAsInt());
        } else {
            ps.setNull(i++, java.sql.Types.INTEGER);
        }
        ps.setBytes(i, nullIfEmpty(mirror.mirroredMessage()));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private void bindRibUpsert(Connection conn, PreparedStatement ps, RouteMonitorMessage msg,
            RibKey key) throws SQLException {
        int i = 1;
        ps.setObject(i++, key.peerId());                                              // peer_id
        ps.setString(i++, PgText.cidr(key.prefix(), key.prefixLength(), msg.ipv4())); // prefix
        ps.setObject(i++, msg.header().routerId());                                   // router_id
        setOptInt(ps, i++, msg.originAsn());                                          // origin_as
        ps.setArray(i++, intArray(conn, PgText.asnArray(msg.asPath())));              // as_path
        ps.setString(i++, PgText.inet(msg.nextHop()));                               // next_hop
        setOptInt(ps, i++, msg.med());                                                // med
        setOptInt(ps, i++, msg.localPref());                                          // local_pref
        ps.setInt(i++, msg.origin());                                                 // origin
        ps.setArray(i++, intArray(conn, PgText.intArray(msg.communities())));         // communities
        ps.setArray(i++, textArray(conn, PgText.largeCommunities(msg.largeCommunities())));
        ps.setArray(i++, textArray(conn, PgText.extCommunities(msg.extendedCommunities())));
        ps.setNull(i++, java.sql.Types.INTEGER);                                      // vprn_id
        ps.setArray(i++, textArray(conn, PgText.strings(msg.routeTargets())));         // route_target
        ps.setBoolean(i++, msg.ipv4());                                               // is_ipv4
        ps.setBoolean(i++, msg.prePolicy());                                          // is_prepolicy
        ps.setString(i++, (msg.peerRd() == null || msg.peerRd().isBlank())
                ? null : msg.peerRd());                                               // peer_rd
        if (msg.pathId().isPresent() && msg.pathId().getAsLong() > 0) {
            ps.setInt(i++, (int) msg.pathId().getAsLong());                           // path_id
        } else {
            ps.setNull(i++, java.sql.Types.INTEGER);
        }
        ps.setObject(i, PgText.ts(msg.header().timestampNanos()));                    // timestamp
    }

    // --- prepared-statement helpers ---

    private static java.sql.Array intArray(Connection conn, Integer[] values) throws SQLException {
        return values == null ? null : conn.createArrayOf("int4", values);
    }

    private static java.sql.Array textArray(Connection conn, String[] values) throws SQLException {
        return values == null ? null : conn.createArrayOf("text", values);
    }

    private static void setOptInt(PreparedStatement ps, int index, java.util.OptionalLong value)
            throws SQLException {
        if (value.isPresent()) {
            ps.setInt(index, (int) value.getAsLong());
        } else {
            ps.setNull(index, java.sql.Types.INTEGER);
        }
    }

    private static byte[] nullIfEmpty(byte[] value) {
        return (value == null || value.length == 0) ? null : value;
    }

    /**
     * Runs the given unit of work inside a single transaction: auto-commit is disabled, the
     * work executes, and the connection is committed on success or rolled back on failure.
     * Any checked {@link SQLException} is rethrown as an unchecked {@link StoreWriteException}
     * so that the {@link StoreWriter} all-or-nothing contract surfaces as a propagating
     * runtime exception.
     */
    /**
     * Runs the given unit of work on an auto-commit connection: each statement commits on its own,
     * so no explicit {@code BEGIN}/{@code COMMIT} round trip is spent. Used by the two high-volume
     * paths, whose work is either a single atomic {@code COPY} or an idempotent, rebuildable
     * projection and therefore needs no surrounding transaction. Hikari hands out connections in
     * auto-commit mode, so the guard below is normally a no-op.
     */
    private void inAutoCommit(SqlWork work) {
        try (Connection connection = dataSource.getConnection()) {
            if (!connection.getAutoCommit()) {
                connection.setAutoCommit(true);
            }
            work.run(connection);
        } catch (SQLException e) {
            throw new StoreWriteException("Store write failed", e);
        }
    }

    private void inTransaction(SqlWork work) {
        try (Connection connection = dataSource.getConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                work.run(connection);
                connection.commit();
            } catch (SQLException | RuntimeException e) {
                safeRollback(connection);
                throw e instanceof RuntimeException re
                        ? re
                        : new StoreWriteException("Store write failed", e);
            } finally {
                restoreAutoCommit(connection, previousAutoCommit);
            }
        } catch (SQLException e) {
            throw new StoreWriteException("Could not obtain or close database connection", e);
        }
    }

    private static void safeRollback(Connection connection) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            // Preserve the original failure; nothing actionable on a failed rollback.
        }
    }

    private static void restoreAutoCommit(Connection connection, boolean previous) {
        try {
            connection.setAutoCommit(previous);
        } catch (SQLException ignored) {
            // The connection is being returned to the pool; restoration is best-effort.
        }
    }

    /** A unit of transactional JDBC work that may throw {@link SQLException}. */
    @FunctionalInterface
    private interface SqlWork {
        void run(Connection connection) throws SQLException;
    }
}
