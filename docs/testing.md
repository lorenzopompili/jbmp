# Testing strategy

**Rule: the test suite runs with zero external infrastructure.** `./mvnw test` must pass
offline, with no Kafka broker, no database and no network services. Tests against real
infrastructure are reserved for a final, explicitly-run integration phase.

## Layers

1. **Protocol / parser / codec (`jbmp-shared`)** — plain JUnit 5 unit tests over byte
   arrays. Each BMP message type and BGP attribute/family has:
   - positive tests with realistic byte vectors,
   - negative tests for truncated/malformed input (must raise a typed parse error, never
     `NullPointerException` or `ArrayIndexOutOfBoundsException`),
   - round-trip tests for the wire codec (encode → decode → equals).

2. **Kafka path (`jbmp-collector`, `jbmp-consumer`)** — an **embedded broker**
   (`spring-kafka-test`) is used; no external Kafka. Producer/consumer wiring,
   serialization and partitioning are asserted in-process.

3. **Storage layer (`jbmp-consumer`)** — the store is accessed through an interface
   (`StoreWriter`). Unit tests exercise batching, flushing and offset-after-write logic
   against an **in-memory fake** (`InMemoryStoreWriter`); even the embedded-broker
   integration test wires the consumer to that fake. There are **no database-backed tests**
   yet: the binary `COPY` and upsert path against PostgreSQL/TimescaleDB is validated
   end-to-end with `jbmp-mock` against a live database, outside the JUnit suite. A
   Testcontainers-backed PostgreSQL test is a candidate future addition — the build already
   reserves the `integration` tag for it.

4. **End-to-end conformance** — `jbmp-mock` generates RFC-conformant byte sequences that
   double as golden vectors for the parser. Mock-driven tests validate the collector
   in-process (loopback TCP), still without external services.

## Conventions

- No `Thread.sleep()` in tests; use awaitility-style polling or test clocks.
- Integration tests carry the JUnit tag `integration` and are skipped unless explicitly
  enabled.
- Coverage target for `jbmp-shared`: 80%+.
