# Architecture

jBMP is a small platform of cooperating services built around a single pure-Java
protocol library. The design goals, in order: **correctness** (RFC-faithful parsing
that never silently drops data), **throughput** (hundreds of thousands of messages per
second on commodity hardware), and **operability** (clean configuration and metrics).

## Modules and dependencies

```
                jbmp-shared  (pure Java: model + parser + builder + wire codec + identity)
                  ▲     ▲     ▲
        ┌─────────┘     │     └──────────┐
  jbmp-collector   jbmp-consumer    jbmp-mock
        ▲               ▲                ▲
        └───────────────┴────────────────┘
                     jbmp-all  (launcher: boots one role)
```

- **jbmp-shared** has no framework dependencies (only SLF4J). It is the contract shared
  by every other module and is independently testable and publishable.
- **jbmp-collector**, **jbmp-consumer**, **jbmp-mock** are independent Spring Boot
  services that depend only on `jbmp-shared`'s public API.
- **jbmp-all** depends on the three services and selects one at startup.

## Data flow

```
routers ──TCP──▶ collector ──Kafka──▶ consumer ──bulk copy──▶ time-series store
                    │                      │
                    ├─ parse BMP/BGP       ├─ batch (size or time)
                    ├─ enrich (optional)   ├─ idempotent routing-state upserts
                    └─ publish + raw       └─ commit offset AFTER store write
```

1. A router opens a BMP session over TCP. The collector parses the BMP common header,
   per-peer header and the carried BGP message.
2. Messages are optionally enriched (origin AS, route distinguisher, route targets)
   and published to Kafka, keyed so that all messages from one router land on the same
   partition (preserving per-router ordering).
3. The consumer accumulates messages into batches and writes them to the store using
   bulk copy for the high-volume path and idempotent upserts for routing state.
4. Kafka offsets are committed only after a successful store write, so a crash or
   rebalance re-reads rather than loses data.

## Concurrency model

The collector uses **one virtual thread per connected router**, performing blocking
reads. This keeps the per-connection code straightforward (read header → read body →
parse → handle) while scaling to large numbers of concurrent sessions, since virtual
threads unmount while blocked on I/O. Parsing runs inline on the carrier thread.

Each connection owns a **reusable, thread-confined read buffer**, so the hot path takes
no locks and produces minimal garbage.

## Consumer write path

The consumer is shaped so the high-volume historical write never stalls behind anything else:

- **Two isolated listeners.** The two route-monitor topics are consumed by one container (one
  thread per assigned partition) that does only the bulk write; the lower-volume peer-event,
  stats and route-mirror topics are consumed by a separate, smaller container — so a burst of
  statistics can never head-of-line-block a route-monitor write.
- **Binary `COPY`.** The append-only `route_monitor` history is written with PostgreSQL's binary
  `COPY` of the full BGP attribute set: `cidr`/`inet` addresses, `int4[]`/`text[]`/`uuid[]`
  arrays, and structured EVPN/FlowSpec/SR-Policy/BGP-LS as `jsonb`. A single `COPY` on an
  auto-commit connection is atomic, so the Kafka offset is committed straight after the rows are
  durable.
- **Decoupled RIB projection.** The current-state `rib_state` (one row per peer + prefix,
  hash-partitioned on `peer_id` with `fillfactor` headroom for HOT updates) is maintained by a
  single background worker off the offset-commit path; it is fully rebuildable from the history.
- **Router identity from the source IP**, so a given router maps to a stable Kafka partition and
  consumer thread.

## Performance principles

- **Hybrid allocation strategy.** Low-frequency messages use the immutable record model
  for clarity. The high-volume route-monitoring path is parsed and re-serialized with
  minimal intermediate objects: reused buffers, primitive arrays (`long[]`, `int[]`)
  instead of boxed collections, and single-pass parse-then-encode where possible.
- **No defensive copies on the hot path.** Raw protocol bytes are passed through without
  copying where ownership allows it; copies are reserved for retained, low-frequency state.
- **Capacity-hinted collections** to avoid resize churn.
- **GC**: Generational ZGC is the recommended collector for the low-pause, high-allocation
  profile; this is validated by load testing before any throughput claim is made.

## Observability

Each service exposes health and Prometheus metrics via Spring Boot Actuator and
Micrometer (`/actuator/prometheus`). Metric names are stable and documented per service.

## Build and deployment

- A single Maven reactor builds all modules; the Maven Wrapper (`./mvnw`) pins the
  Maven version so no global install is required.
- Production runs the three services independently so they scale and fail in isolation.
- `jbmp-all` provides a single runnable jar for development, demos and single-host setups.
