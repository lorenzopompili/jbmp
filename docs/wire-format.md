# Wire format

The collector and consumer exchange parsed, optionally enriched messages over Kafka
using a compact custom **binary** encoding. A schema-based format (e.g. Protobuf) was
considered and deliberately not used: the binary codec minimises serialization overhead
and allocation on the highest-volume path. Both producer and consumer live in this
project, so the format is internal and versioned together.

> The exact per-field byte layout is finalized together with the codec implementation in
> `jbmp-shared` and is covered by round-trip tests (encode → decode → equals). This
> document fixes the **conventions**; the field tables are completed alongside the code.

## Conventions

- **Endianness**: big-endian for all integers.
- **Layout**: fixed-size headers followed by length-prefixed variable-length fields.
- **Length prefixes** use one of two widths, chosen per field:
  - `uint16` for fields bounded below 64 KiB (prefixes, addresses, counters, AS-path and
    community arrays);
  - `uint32` for fields that may exceed 64 KiB (structured blobs for extended address
    families, raw mirrored payloads, capability/OPEN payloads, free text).
- **Forward compatibility**: new fields are appended; a decoder that reaches end-of-buffer
  before reading an appended field treats it as absent. Decoders never fail on trailing
  unknown bytes.
- **No silent truncation**: any field that does not fit its declared length is a decode
  error, not a silent cut.

## Identity

Routers and peers are identified by **deterministic UUIDs** derived with SHA-256 over a
fixed set of stable inputs, so the same router/peer always maps to the same identifier.
This makes downstream upserts idempotent without coordination. The exact input byte order
is specified next to the implementation and locked by tests.

## Message families

| Family | Carries | Volume |
|---|---|---|
| Route monitoring | one route announcement/withdrawal (prefix + path attributes + enrichment) | very high |
| Peer event | peer up/down with session and error details | low |
| Statistics report | per-peer counters | low |
| Route mirror | a raw mirrored BGP message (diagnostics) | low |

Route monitoring is split by address family (IPv4 / IPv6) at the topic level so the two
streams can be partitioned and scaled independently.

## Topics

Topic names, partition counts and retention are configuration, not hard-coded. Defaults
are documented with the collector's Kafka producer configuration.
