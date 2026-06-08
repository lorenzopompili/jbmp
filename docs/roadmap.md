# Roadmap

Phased plan. Each phase is completed and tested before the next begins. All tests run
without external infrastructure (see [testing.md](testing.md)).

- **Phase 0 — Scaffolding.** Maven reactor, five modules, Java 25, Spring Boot platform
  BOM, Maven Wrapper, license, base documentation. *(done)*

- **Phase 1 — Domain model (`jbmp-shared`).** Immutable model for all BMP message types
  (including Route Mirroring) and the full BGP attribute set, using records and sealed
  interfaces. A lightweight `ByteReader` abstraction keeps the core free of any buffer
  framework. *(done)*

- **Phase 2 — BMP parser (`jbmp-shared`).** Common header, per-peer header, and every
  message type. Tolerant and strict parse modes. *(done)*

- **Phase 3 — BGP-4 UPDATE parser (`jbmp-shared`).** Withdrawn routes, path attributes
  (incl. extended-length, AS-path with 2/4-byte handling and confederation segments,
  communities, large communities, extended communities, route-reflection attributes),
  and NLRI. Graceful degradation on unknown attributes. *(done)*

- **Phase 4 — Multiprotocol and extended families (`jbmp-shared`).** MP_REACH/MP_UNREACH
  with all next-hop variants, L3VPN, EVPN, FlowSpec, SR Policy, BGP-LS, a raw catch-all
  for unknown families, ADD-PATH, and End-of-RIB detection. The consumer decodes EVPN,
  FlowSpec, SR-Policy and BGP-LS to structured `jsonb`. *(done)*

- **Phase 5 — Wire codec and identity (`jbmp-shared`).** Binary serializer/deserializer
  for the enriched message families and deterministic identifiers, with round-trip tests.
  This is the allocation-optimised hot path. *(done)*

- **Phase 6 — Mock (`jbmp-mock`).** Traffic builders and scenarios; source of golden
  vectors that retro-validate the parser. The `stress` scenario emits the full attribute
  set so the pipeline can be exercised end-to-end without an external generator. *(done)*

- **Phase 7 — Collector (`jbmp-collector`).** Virtual-thread TCP listener, enrichment,
  Kafka producer (partitioning, compression, batching) and metrics. *(done)*

- **Phase 8 — Consumer (`jbmp-consumer`).** Kafka consumer, batching, bulk-copy store
  writer behind an interface, idempotent routing-state upserts, offset-after-write,
  schema migrations. *(done)*

- **Phase 9 — Throughput and soak.** Load testing with the mock, micro-benchmarks, GC and
  allocation profiling. *(done)*

- **Phase 10 — Release.** Documentation, examples, packaging and publication. *(done)*
