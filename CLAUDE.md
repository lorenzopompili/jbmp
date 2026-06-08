# CLAUDE.md

Guidance for Claude Code (and other AI assistants) working in this repository.

## What this is

jBMP is a BGP Monitoring Protocol (BMP, RFC 7854) collector platform on Spring Boot 4 and Java 25
virtual threads. It is a Maven multi-module reactor:

- `jbmp-shared` — pure-Java BMP/BGP model, parsers, builders, deterministic UUIDs, binary wire
  codec. **No framework dependencies.**
- `jbmp-collector` — TCP BMP listener (one virtual thread per router) → parse → enrich → Kafka.
- `jbmp-consumer` — Kafka → batched binary `COPY` into PostgreSQL/TimescaleDB + `rib_state` upsert.
- `jbmp-mock` — BMP traffic generator for tests/benchmarks.
- `jbmp-all` — single launcher that boots any role.

## Build & test

- **JDK 25 is required.** Use the bundled wrapper: `./mvnw` (POSIX) / `.\mvnw.cmd` (Windows). If
  `JAVA_HOME` is unset, point it at a JDK 25 before invoking the wrapper.
- Full build: `./mvnw clean install`.
- **Unit tests run with zero external infrastructure** and must stay that way. Run them with
  `./mvnw -DexcludedGroups=integration test`. Tests that need a broker/DB/cluster are tagged
  `@Tag("integration")` and are excluded by default.
- Build one module with its deps: `./mvnw -pl jbmp-consumer -am -DexcludedGroups=integration test`.

## Conventions

- **RFC-faithful and lossless.** Parsers must never silently drop data; unknown/optional attributes
  are preserved. Reference the relevant RFC in Javadoc for protocol types.
- **Document public types** with full Javadoc. Match the comment density, naming and idioms of the
  surrounding code.
- Prefer immutable `record`s and sealed hierarchies for the message model; keep `jbmp-shared` free
  of Spring/Kafka/JDBC dependencies.
- The consumer hot path is performance-sensitive — favour bulk operations and avoid per-record
  allocations or per-record round trips on the route-monitor path.

## Wire format

The collector and consumer exchange messages over Kafka in a custom length-prefixed **binary**
encoding in `jbmp-shared/.../wire/WireCodec.java`. It is intentionally not a schema-registry
format. On any incompatible change, bump `WireCodec.FORMAT_VERSION` and keep the decoder
backward-compatible where practical (there are forward-compat tests).

## Persistence

Schema lives in Flyway migrations under `jbmp-consumer/src/main/resources/db/migration` (`V*.sql`).
`route_monitor` (append-only history) is written with binary `COPY` via `RouteMonitorCopy`;
`rib_state` (current state, one row per `(peer, prefix)`) is an idempotent `INSERT … ON CONFLICT`
upsert / `DELETE`. Both carry the full BGP attribute set (cidr/inet, native arrays, jsonb). The
TimescaleDB hypertable/compression migrations are guarded and no-op on vanilla PostgreSQL.

## Secrets & local files

- **Never commit secrets.** Real endpoints/credentials live in a git-ignored `.env` (see
  `.env.example`). Benchmark scripts, JFR captures and logs are local-only and git-ignored.
- Keep the repository self-contained and publishable: no machine-specific paths or credentials in
  committed files.
