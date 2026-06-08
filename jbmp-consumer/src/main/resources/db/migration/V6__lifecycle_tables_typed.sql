-- Make the lifecycle/counter tables type-consistent with the fully-typed route tables.
--
-- peer_events, bmp_stats and route_mirror were created in V1 with BYTEA router_id/peer_id and
-- BIGINT (epoch-nanoseconds) event_time/received_at, whereas route_monitor (V4) and rib_state (V5)
-- already store identities as native UUID and timestamps as TIMESTAMPTZ. This migration converts
-- ONLY those columns on the three lifecycle tables; every other column (remote/local IP/ASN/BGP
-- identifier, ports, peer_rd, error fields, OPEN messages, info_data, stat_type/value,
-- information_code, mirrored_message) keeps its V1 type and meaning, and no recorded field is
-- dropped.
--
-- These tables are low-volume and transient in the bench, so a DROP/CREATE is safe rather than a
-- column-by-column ALTER. The hypertable conversion mirrors V4: TimescaleDB partitions on the
-- TIMESTAMPTZ event_time with a 1-day chunk interval, guarded by the extension check so a plain
-- PostgreSQL server is unaffected. Indexes are recreated unchanged.

-- Peer up/down lifecycle events (RFC 7854 Sections 4.9, 4.10).
DROP TABLE IF EXISTS peer_events CASCADE;

CREATE TABLE peer_events (
    event_time        TIMESTAMPTZ NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL,
    collector_id      BIGINT      NOT NULL,
    router_id         UUID        NOT NULL,
    peer_id           UUID        NOT NULL,
    event_type        TEXT        NOT NULL,
    remote_ip         BYTEA,
    remote_asn        BIGINT,
    remote_bgp_id     BYTEA,
    local_ip          BYTEA,
    local_asn         BIGINT,
    local_bgp_id      BYTEA,
    remote_port       INTEGER,
    local_port        INTEGER,
    peer_rd           TEXT,
    bmp_reason        INTEGER,
    bgp_error_code    INTEGER,
    bgp_error_subcode INTEGER,
    error_text        TEXT,
    sent_open         BYTEA,
    received_open     BYTEA,
    info_data         TEXT
);

-- Statistics Report counters (RFC 7854 Section 4.8), one row per (report, stat type).
DROP TABLE IF EXISTS bmp_stats CASCADE;

CREATE TABLE bmp_stats (
    event_time    TIMESTAMPTZ NOT NULL,
    received_at   TIMESTAMPTZ NOT NULL,
    collector_id  BIGINT      NOT NULL,
    router_id     UUID        NOT NULL,
    peer_id       UUID        NOT NULL,
    stat_type     INTEGER     NOT NULL,
    stat_value    BIGINT      NOT NULL
);

-- Route Mirroring events (RFC 7854 Section 4.7): verbatim BGP PDUs.
DROP TABLE IF EXISTS route_mirror CASCADE;

CREATE TABLE route_mirror (
    event_time        TIMESTAMPTZ NOT NULL,
    received_at       TIMESTAMPTZ NOT NULL,
    collector_id      BIGINT      NOT NULL,
    router_id         UUID        NOT NULL,
    peer_id           UUID        NOT NULL,
    information_code  INTEGER,
    mirrored_message  BYTEA
);

-- Optional TimescaleDB acceleration: convert the recreated tables to hypertables partitioned on
-- their now-TIMESTAMPTZ event_time (1-day chunks), matching V4's layout. Guarded by the extension
-- check, so this is a no-op on a plain PostgreSQL server.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('peer_events', 'event_time',
            chunk_time_interval => INTERVAL '1 day',
            create_default_indexes => FALSE);
        PERFORM create_hypertable('bmp_stats', 'event_time',
            chunk_time_interval => INTERVAL '1 day',
            create_default_indexes => FALSE);
        PERFORM create_hypertable('route_mirror', 'event_time',
            chunk_time_interval => INTERVAL '1 day',
            create_default_indexes => FALSE);
    END IF;
END $$;

CREATE INDEX idx_peer_events_peer_time  ON peer_events (peer_id, event_time);
CREATE INDEX idx_bmp_stats_peer_time    ON bmp_stats (peer_id, event_time);
CREATE INDEX idx_route_mirror_peer_time ON route_mirror (peer_id, event_time);
