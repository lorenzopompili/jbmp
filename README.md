# jBMP

High-throughput **BGP Monitoring Protocol (BMP)** collector platform for the JVM.

jBMP ingests BMP sessions from routers over TCP, parses the BMP envelope (RFC 7854) and the
carried BGP-4 messages (RFC 4271 and the multiprotocol/extended families), enriches them with a
deterministic provenance header, and ships them through Kafka to a consumer that persists them in
a PostgreSQL/TimescaleDB time-series store. It is built on **Spring Boot 4** and **Java 25 virtual
threads** — one thread per router, blocking reads, no reactive machinery — and is designed for very
high message rates.

## Highlights

- **One virtual thread per router.** The collector handles thousands of concurrent BMP sessions
  with simple blocking I/O; the JVM schedules them onto a small carrier pool.
- **Custom binary wire format.** Parsed messages cross Kafka in a compact, length-prefixed binary
  encoding (no schema registry, no reflection) — see [docs/wire-format.md](docs/wire-format.md).
- **Bulk binary `COPY` persistence.** The consumer writes the historical table with PostgreSQL's
  binary `COPY` protocol and maintains an idempotent current-state (`rib_state`) projection.
- **Decoupled hot path.** Route-monitor and low-volume (peer/stats/mirror) topics are consumed by
  separate listener containers, so a burst of statistics never stalls the bulk-load path.
- **RFC-faithful, lossless parsing.** The full BGP attribute set is parsed and stored: AS_PATH and
  its segments, standard/large/extended communities, aggregator, route-reflector attributes, L3VPN
  route targets, and the multiprotocol families.

## Protocols

| Area | RFCs |
|---|---|
| BMP | 7854 |
| BGP-4 | 4271 |
| Multiprotocol BGP | 4760 |
| Communities | 1997, 4360 (extended), 8092 (large) |
| Route reflection | 4456 (ORIGINATOR_ID, CLUSTER_LIST) |
| Four-octet ASNs | 6793 |
| ADD-PATH | 7911 |
| L3VPN | 4364 |
| EVPN | 7432 |
| Flow Specification | 8955 |
| BGP-LS | 7752 |
| Graceful Restart / End-of-RIB | 4724 |

## Modules

| Module | Type | Responsibility |
|---|---|---|
| `jbmp-shared` | library (pure Java) | BMP/BGP message model, parsers, builders, deterministic UUIDs and the binary wire codec. No framework dependencies. |
| `jbmp-collector` | Spring Boot app | TCP listener (one virtual thread per router) → parse → enrich → Kafka producer. |
| `jbmp-consumer` | Spring Boot app | Kafka consumer → batched binary `COPY` into PostgreSQL/TimescaleDB + `rib_state` projection. |
| `jbmp-mock` | Spring Boot app | BMP traffic generator for end-to-end tests and benchmarks; the `stress` scenario emits the full attribute set (multi-segment AS_PATH, all community types, route targets, RR attributes and EVPN/FlowSpec/SR-Policy/BGP-LS routes). |
| `jbmp-all` | Spring Boot app | Single runnable jar that boots any role, for development and demos. |

Each application module produces a normal library jar plus an executable jar with the `boot`
classifier (e.g. `jbmp-collector-<version>-boot.jar`). The three roles are independent services in
production; `jbmp-all` bundles them into one jar for convenience.

## Data flow

```
routers --BMP/TCP--> [collector] --binary wire--> Kafka --> [consumer] --binary COPY--> TimescaleDB
   (1 virtual thread per router)   (key = router id)        (route_monitor + rib_state)
```

The Kafka record key is the router identity (a deterministic UUID of the router's source IP), so
all traffic from one router lands on one partition and preserves per-router ordering. Throughput
scales with the number of distinct routers (hence active partitions and consumer threads).

## Requirements

- JDK 25 (LTS)
- No global Maven needed — use the bundled Maven Wrapper (`./mvnw`).
- For the consumer: a Kafka cluster and a PostgreSQL 14+ database (TimescaleDB optional).

## Build

```bash
./mvnw clean install          # Linux/macOS
.\mvnw.cmd clean install      # Windows
```

The unit-test suite runs with **zero external infrastructure**. Integration tests (embedded
broker / Testcontainers / live cluster) are tagged `integration` and excluded by default.

## Configuration

Copy [`.env.example`](.env.example) to `.env` and set your endpoints/credentials (the real `.env`
is git-ignored). Every value maps to a standard Spring property and can also be passed as a
`--spring....` flag. Key settings:

| Env var | Default | Meaning |
|---|---|---|
| `SPRING_KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka bootstrap servers |
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/jbmp` | consumer JDBC URL |
| `SPRING_DATASOURCE_USERNAME` / `_PASSWORD` | `jbmp` / `jbmp` | DB credentials |
| `SPRING_FLYWAY_ENABLED` | `false` | apply schema migrations on startup |
| `JBMP_CONSUMER_STORE` | in-memory | set to `jdbc` for the PostgreSQL sink |
| `JBMP_COLLECTOR_BMP_PORT` | `1790` | BMP TCP listen port |

## Run

Standalone executable jars:

```bash
java -jar jbmp-collector/target/jbmp-collector-0.1.0-SNAPSHOT-boot.jar
java -jar jbmp-consumer/target/jbmp-consumer-0.1.0-SNAPSHOT-boot.jar
java -jar jbmp-mock/target/jbmp-mock-0.1.0-SNAPSHOT-boot.jar
```

All-in-one launcher (select the role as the first argument):

```bash
java -jar jbmp-all/target/jbmp-all-0.1.0-SNAPSHOT.jar collector
java -jar jbmp-all/target/jbmp-all-0.1.0-SNAPSHOT.jar consumer
java -jar jbmp-all/target/jbmp-all-0.1.0-SNAPSHOT.jar mock
```

## Persistence

The consumer's schema (Flyway migrations under
`jbmp-consumer/src/main/resources/db/migration`) models the data as:

- **`route_monitor`** — append-only history of every route-monitoring event, with the full
  attribute set (`prefix` as `cidr`, `next_hop` as `inet`, AS_PATH/communities as native arrays,
  AS-path segments / EVPN / FlowSpec / SR-Policy / BGP-LS as `jsonb`). Written via binary `COPY`;
  a TimescaleDB hypertable with compression where the extension is present, a plain table otherwise.
- **`rib_state`** — the current routing state, one row per `(peer, prefix)`, maintained by an
  idempotent `INSERT … ON CONFLICT` upsert (announce) / `DELETE` (withdraw). Hash-partitioned on
  `peer_id` with `fillfactor` headroom for HOT updates.
- `peer_events`, `bmp_stats`, `route_mirror` — peer lifecycle, statistics reports and mirrored
  PDUs, fully typed (`uuid` / `timestamptz`) and consistent with the tables above.

## Performance

jBMP is built for sustained bulk ingest, not request/response latency. The dominant cost is the
database write, so the design minimises it: binary `COPY`, an off-path single-writer for the
`rib_state` projection, and listener decoupling so the bulk path never blocks behind low-volume
writes.

Throughput scales with parallelism. Over a network-attached TimescaleDB a single partition (one
router's worth of traffic) sustains tens of thousands of rows/second; spread across many routers
(hence partitions and consumer threads) it scales near-linearly — hundreds of thousands of
rows/second of bursts have been observed across a few dozen partitions. The exact figures depend
on row width, indexes, and the database's WAL/checkpoint and network characteristics.

## Known limitations

- BGP-LS TLVs and FlowSpec component values outside the commonly-used set are preserved as hex
  within the structured JSON rather than expanded into named fields. No data is lost.

## Documentation

See [docs/](docs/): [architecture](docs/architecture.md), [wire format](docs/wire-format.md),
[testing strategy](docs/testing.md) and [roadmap](docs/roadmap.md).

## Contributing

Issues and pull requests are welcome. Please keep the unit-test suite green and infrastructure-free
(`./mvnw -DexcludedGroups=integration test`), match the surrounding code style, and document public
types with RFC references where relevant. Working with an AI assistant? See [CLAUDE.md](CLAUDE.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
