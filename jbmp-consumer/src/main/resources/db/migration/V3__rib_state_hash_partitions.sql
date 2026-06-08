-- Hash-partition the current routing-state projection for an UPDATE-intensive workload.
--
-- rib_state is hit by a continuous stream of INSERT ... ON CONFLICT DO UPDATE / DELETE keyed by
-- (peer_id, prefix, prefix_len, path_id). On a single flat table every upsert maintains one large
-- B-tree and competes for the same heap pages, so the projection becomes the heaviest database
-- consumer under load. Splitting it into 32 hash partitions on peer_id gives 32 proportionally
-- smaller, shallower indexes with better cache locality, and confines each upsert/delete (which
-- always pins a single peer_id) to one partition. fillfactor=80 reserves in-page room so steady
-- re-advertisements update HOT (no index churn, no page splits), and the aggressive autovacuum
-- settings keep the churn-heavy partitions from bloating.
--
-- The projection is fully rebuildable from the append-only route_monitor history, so dropping and
-- recreating the (transient) table here is safe.

DROP TABLE IF EXISTS rib_state CASCADE;

CREATE TABLE rib_state (
    peer_id       BYTEA       NOT NULL,
    prefix        BYTEA       NOT NULL,
    prefix_len    INTEGER     NOT NULL,
    path_id       BIGINT      NOT NULL,
    router_id     BYTEA       NOT NULL,
    action        TEXT        NOT NULL,
    next_hop      BYTEA,
    origin_asn    BIGINT,
    med           BIGINT,
    local_pref    BIGINT,
    event_time    BIGINT      NOT NULL,
    received_at   BIGINT      NOT NULL,
    PRIMARY KEY (peer_id, prefix, prefix_len, path_id)
) PARTITION BY HASH (peer_id);

-- 32 hash partitions over peer_id. The conflict arbiter (the primary key) includes the partition
-- key, so INSERT ... ON CONFLICT routes and resolves within a single partition.
--
-- The UPDATE-intensive tuning is applied per partition, not on the parent: a partitioned table
-- has no storage of its own, so PostgreSQL rejects storage parameters (fillfactor, autovacuum)
-- on the parent. Each leaf partition reserves in-page room (fillfactor=80) so steady
-- re-advertisements update HOT — no index churn, no page splits — and runs autovacuum
-- aggressively so the churn-heavy partitions do not bloat.
DO $$
BEGIN
    FOR i IN 0..31 LOOP
        EXECUTE format(
            'CREATE TABLE rib_state_p%s PARTITION OF rib_state '
            || 'FOR VALUES WITH (MODULUS 32, REMAINDER %s) '
            || 'WITH (fillfactor = 80, '
            || 'autovacuum_vacuum_scale_factor = 0.01, '
            || 'autovacuum_analyze_scale_factor = 0.005, '
            || 'autovacuum_vacuum_cost_delay = 2)',
            lpad(i::text, 2, '0'), i
        );
    END LOOP;
END $$;

-- Secondary lookup by advertising router (the peer/prefix lookups are served by the primary key).
CREATE INDEX idx_rib_state_router ON rib_state (router_id);
