-- Rebuild route_monitor with the full BGP attribute set.
--
-- The historical table must persist every attribute carried on the wire — AS_PATH and its
-- structured segments, standard/large/extended communities, aggregator, route-reflector
-- attributes (ORIGINATOR_ID, CLUSTER_LIST), L3VPN route targets, MPLS labels, and the opaque
-- EVPN/FlowSpec/SR-Policy/BGP-LS/raw-NLRI families — not the lean subset the first cut stored.
-- The column names, types and on-disk encodings mirror the reference relational model exactly so
-- the two systems digest and store identical data.
--
-- Network values use native types (cidr/inet) and identities use uuid; arrays use the native
-- PostgreSQL array types; the structured families are jsonb. Timestamps are timestamptz.

DROP TABLE IF EXISTS route_monitor CASCADE;

CREATE TABLE route_monitor (
    received_at         TIMESTAMPTZ NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL,
    collector_id        SMALLINT    NOT NULL DEFAULT 0,
    router_id           UUID        NOT NULL,
    peer_id             UUID        NOT NULL,
    action              SMALLINT    NOT NULL,
    is_end_of_rib       BOOLEAN     NOT NULL DEFAULT FALSE,
    prefix              CIDR        NOT NULL,
    is_ipv4             BOOLEAN     NOT NULL,
    origin_as           INT,
    as_path             INT[],
    as_path_len         SMALLINT,
    next_hop            INET,
    med                 INT,
    local_pref          INT,
    origin              SMALLINT,
    atomic_agg          BOOLEAN,
    aggregator_as       INT,
    aggregator_ip       INET,
    communities         INT[],
    large_communities   TEXT[],
    ext_communities     TEXT[],
    vprn_id             INT,
    route_target        TEXT[],
    peer_rd             TEXT,
    ls_attrs            JSONB,
    is_prepolicy        BOOLEAN     NOT NULL,
    is_locrib           BOOLEAN     NOT NULL DEFAULT FALSE,
    kafka_partition     SMALLINT,
    kafka_offset        BIGINT,
    path_id             INT,
    mpls_labels         INT[],
    originator_id       UUID,
    cluster_list        UUID[],
    as_path_segments    JSONB,
    evpn_data           JSONB,
    flowspec_data       JSONB,
    sr_policy_data      JSONB,
    raw_nlri            JSONB
);

-- TimescaleDB hypertable on received_at (1-day chunks), matching the reference layout. No-op on a
-- plain server: the conversion is guarded by the extension check.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('route_monitor', 'received_at',
            chunk_time_interval => INTERVAL '1 day',
            create_default_indexes => FALSE);

        ALTER TABLE route_monitor SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'peer_id, is_ipv4',
            timescaledb.compress_orderby = 'received_at DESC');
    END IF;
END $$;

-- Same secondary indexes as the reference model (kept during ingest, so write amplification is
-- comparable).
CREATE INDEX idx_route_monitor_peer_time   ON route_monitor (peer_id, received_at DESC);
CREATE INDEX idx_route_monitor_prefix      ON route_monitor (prefix);
CREATE INDEX idx_route_monitor_origin_as   ON route_monitor (origin_as, received_at DESC)
    WHERE origin_as IS NOT NULL;
CREATE INDEX idx_route_monitor_vprn        ON route_monitor (vprn_id, received_at DESC)
    WHERE vprn_id IS NOT NULL;
CREATE INDEX idx_route_monitor_kafka       ON route_monitor (kafka_partition, kafka_offset);
