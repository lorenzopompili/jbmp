-- Optional TimescaleDB acceleration for the high-volume, time-series tables.
--
-- This migration is a no-op on a plain PostgreSQL server: every statement is guarded by a
-- check for the TimescaleDB extension, so the base schema from V1 remains fully usable
-- without it. Where TimescaleDB IS available, the append-only event tables are converted to
-- hypertables partitioned on their nanosecond event_time, which is the standard layout for
-- efficient time-range queries and retention/compression policies.
--
-- The conversion uses create_hypertable(..., migrate_data => TRUE) so it is safe to run
-- against tables that already contain rows.

DO $$
BEGIN
    -- Only act when the TimescaleDB extension is actually installed in this database.
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN

        -- route_monitor: highest-volume table; 1-day chunks over nanosecond timestamps.
        IF NOT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_name = 'route_monitor'
        ) THEN
            PERFORM create_hypertable(
                'route_monitor', 'event_time',
                chunk_time_interval => 86400000000000,  -- 1 day in nanoseconds
                migrate_data => TRUE
            );
        END IF;

        -- peer_events: lower volume, daily chunks are ample.
        IF NOT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_name = 'peer_events'
        ) THEN
            PERFORM create_hypertable(
                'peer_events', 'event_time',
                chunk_time_interval => 86400000000000,
                migrate_data => TRUE
            );
        END IF;

        -- bmp_stats: periodic counters, daily chunks.
        IF NOT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_name = 'bmp_stats'
        ) THEN
            PERFORM create_hypertable(
                'bmp_stats', 'event_time',
                chunk_time_interval => 86400000000000,
                migrate_data => TRUE
            );
        END IF;

        -- route_mirror: sporadic, daily chunks.
        IF NOT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_name = 'route_mirror'
        ) THEN
            PERFORM create_hypertable(
                'route_mirror', 'event_time',
                chunk_time_interval => 86400000000000,
                migrate_data => TRUE
            );
        END IF;

    END IF;
END
$$;
