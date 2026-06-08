-- Rebuild rib_state with the full BGP attribute set, mirroring route_monitor and the reference
-- relational model. The current-state projection now carries the same attributes the historical
-- table does (AS_PATH, standard/large/extended communities, route targets, next hop, origin,
-- etc.), so the two systems' projections are column-for-column identical.
--
-- The key is (peer_id, prefix): the prefix is a cidr that already encodes the network length, and
-- the projection keeps one row per advertised prefix per peer. The table is hash-partitioned on
-- peer_id (32 partitions) with fillfactor headroom and aggressive autovacuum for the
-- UPDATE-intensive workload (see V3 for the rationale). Fully rebuildable from route_monitor, so
-- dropping the transient previous shape here is safe.

DROP TABLE IF EXISTS rib_state CASCADE;

CREATE TABLE rib_state (
    peer_id             UUID        NOT NULL,
    prefix              CIDR        NOT NULL,
    router_id           UUID        NOT NULL,
    origin_as           INT,
    as_path             INT[],
    next_hop            INET,
    med                 INT,
    local_pref          INT,
    origin              SMALLINT,
    communities         INT[],
    large_communities   TEXT[],
    ext_communities     TEXT[],
    vprn_id             INT,
    route_target        TEXT[],
    is_ipv4             BOOLEAN     NOT NULL,
    is_prepolicy        BOOLEAN     NOT NULL,
    peer_rd             TEXT,
    path_id             INT,
    timestamp           TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (peer_id, prefix)
) PARTITION BY HASH (peer_id);

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

CREATE INDEX idx_rib_state_prefix    ON rib_state (prefix);
CREATE INDEX idx_rib_state_origin_as ON rib_state (origin_as);
CREATE INDEX idx_rib_state_router    ON rib_state (router_id);
