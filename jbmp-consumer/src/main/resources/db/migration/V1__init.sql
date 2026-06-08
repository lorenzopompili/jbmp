-- jBMP consumer base schema (plain PostgreSQL).
--
-- This migration defines the core relational model populated by the consumer. It uses only
-- standard PostgreSQL features so it applies cleanly to a vanilla server; TimescaleDB-specific
-- hypertable conversion is kept in the separate, optional V2 migration so that environments
-- without the extension are unaffected.
--
-- Conventions:
--   * Identities (router_id, peer_id) are the 16-byte deterministic UUIDs produced by
--     it.lpworks.jbmp.identity.UuidFactory, stored as BYTEA (collector-side wire layout).
--   * Network values (prefix, next_hop, BGP identifiers, OPEN/mirrored PDUs) are stored as
--     BYTEA in their on-the-wire byte form.
--   * Timestamps are BIGINT nanoseconds since the Unix epoch, matching the wire MessageHeader.

-- Routers observed via BMP (RFC 7854).
CREATE TABLE IF NOT EXISTS bmp_routers (
    router_id     BYTEA       PRIMARY KEY,
    name          TEXT,
    address       BYTEA,
    first_seen    BIGINT,
    last_seen     BIGINT
);

-- BGP peers monitored behind each router.
CREATE TABLE IF NOT EXISTS bgp_peers (
    peer_id       BYTEA       PRIMARY KEY,
    router_id     BYTEA       NOT NULL REFERENCES bmp_routers (router_id) ON DELETE CASCADE,
    peer_address  BYTEA,
    peer_asn      BIGINT,
    peer_rd       TEXT,
    first_seen    BIGINT,
    last_seen     BIGINT
);

CREATE INDEX IF NOT EXISTS idx_bgp_peers_router ON bgp_peers (router_id);

-- Append-only historical route-monitoring events (RFC 7854 Section 4.6). High-volume table;
-- written via the PostgreSQL COPY bulk path.
CREATE TABLE IF NOT EXISTS route_monitor (
    event_time    BIGINT      NOT NULL,
    received_at   BIGINT      NOT NULL,
    collector_id  BIGINT      NOT NULL,
    router_id     BYTEA       NOT NULL,
    peer_id       BYTEA       NOT NULL,
    action        TEXT        NOT NULL,
    pre_policy    BOOLEAN     NOT NULL,
    loc_rib       BOOLEAN     NOT NULL,
    ipv4          BOOLEAN     NOT NULL,
    end_of_rib    BOOLEAN     NOT NULL,
    add_path      BOOLEAN     NOT NULL,
    prefix        BYTEA,
    prefix_len    INTEGER     NOT NULL,
    path_id       BIGINT,
    origin_asn    BIGINT,
    next_hop      BYTEA,
    med           BIGINT,
    local_pref    BIGINT,
    origin        INTEGER     NOT NULL,
    peer_rd       TEXT
);

CREATE INDEX IF NOT EXISTS idx_route_monitor_peer_time ON route_monitor (peer_id, event_time);
CREATE INDEX IF NOT EXISTS idx_route_monitor_time ON route_monitor (event_time);

-- Current routing-state projection: at most one row per (peer, prefix, prefix length, path id).
-- Announces upsert, withdraws delete; the consumer keeps this idempotent under re-delivery.
CREATE TABLE IF NOT EXISTS rib_state (
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
);

CREATE INDEX IF NOT EXISTS idx_rib_state_peer ON rib_state (peer_id);

-- Peer up/down lifecycle events (RFC 7854 Sections 4.9, 4.10).
CREATE TABLE IF NOT EXISTS peer_events (
    event_time        BIGINT  NOT NULL,
    received_at       BIGINT  NOT NULL,
    collector_id      BIGINT  NOT NULL,
    router_id         BYTEA   NOT NULL,
    peer_id           BYTEA   NOT NULL,
    event_type        TEXT    NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_peer_events_peer_time ON peer_events (peer_id, event_time);

-- Statistics Report counters (RFC 7854 Section 4.8), one row per (report, stat type).
CREATE TABLE IF NOT EXISTS bmp_stats (
    event_time    BIGINT      NOT NULL,
    received_at   BIGINT      NOT NULL,
    collector_id  BIGINT      NOT NULL,
    router_id     BYTEA       NOT NULL,
    peer_id       BYTEA       NOT NULL,
    stat_type     INTEGER     NOT NULL,
    stat_value    BIGINT      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bmp_stats_peer_time ON bmp_stats (peer_id, event_time);

-- Route Mirroring events (RFC 7854 Section 4.7): verbatim BGP PDUs.
CREATE TABLE IF NOT EXISTS route_mirror (
    event_time        BIGINT  NOT NULL,
    received_at       BIGINT  NOT NULL,
    collector_id      BIGINT  NOT NULL,
    router_id         BYTEA   NOT NULL,
    peer_id           BYTEA   NOT NULL,
    information_code  INTEGER,
    mirrored_message  BYTEA
);

CREATE INDEX IF NOT EXISTS idx_route_mirror_peer_time ON route_mirror (peer_id, event_time);
