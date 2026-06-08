> Draft for Medium / a blog. Free to copy out of the repo. Aseptic: no proprietary references.

# Building a high-throughput BGP/BMP collector in Java with virtual threads

Most of the "fast data pipeline" folklore in the JVM world ends at the same place: *go
reactive, or go home*. Netty, event loops, backpressure operators, the works. I wanted to find
out whether Java 25's virtual threads let you write the boring, blocking, one-thread-per-connection
version — and still move hundreds of thousands of messages a second. So I built **jBMP**, a
collector for the **BGP Monitoring Protocol**, and pushed it until the database begged for mercy.

This is the story of what I built, and — more usefully — the three times I was wrong about where
the time was going.

## What's a BMP collector, and why care about throughput

BMP (RFC 7854) is how a router streams its BGP state to a monitoring station: it opens a TCP
session and pushes a firehose of *route monitoring* messages (every prefix it learns), peer
up/down events, and periodic statistics. A single big edge router or route reflector can dump
**millions** of prefixes when a session comes up. A collector that watches a few hundred routers
has to absorb that initial-dump thundering herd without falling over.

So the shape of the problem is: many long-lived TCP connections, each occasionally bursting huge
volumes of structured binary messages that must be parsed and durably stored. Classic high-fan-in
ingest.

jBMP splits into three services around a pure-Java protocol library:

- a **collector** that terminates BMP/TCP, parses the BMP envelope and the carried BGP-4 messages,
  and produces them to Kafka;
- a **consumer** that drains Kafka and bulk-loads PostgreSQL/TimescaleDB;
- a **mock** router to generate load.

## Decision 1: one virtual thread per router

The collector's core is deliberately dumb:

```java
// one of these runs per connected router, on its own virtual thread
while ((message = readNextBmpMessage(in)) != null) {
    var parsed  = parser.parse(message);
    var enriched = enricher.enrich(parsed, context);
    publisher.publish(enriched);   // to Kafka
}
```

Blocking reads. Blocking parse. No callbacks, no state machine, no reassembly buffer that I have
to thread through an event loop. Each router gets `Thread.ofVirtual().start(...)`, and the JVM
multiplexes thousands of these onto a handful of carrier threads. When a read blocks on the
socket, the virtual thread is parked and its carrier is freed — exactly what an event loop does
for you, except I never had to write the event loop.

This matters beyond aesthetics. BMP framing is stateful (a 6-byte common header gives you the
length, then you read the rest). In a reactive pipeline that becomes a tedious incremental decoder.
With a virtual thread it's a plain `readFully`. The code reads like the spec.

The lesson that surprised me: at no point in the entire performance investigation below did the
threading model show up as a bottleneck. Virtual threads did their job and got out of the way.

## Decision 2: a custom binary wire format, not Protobuf

The collector and consumer talk over Kafka. The obvious move is Protobuf or Avro. I didn't.

A parsed route-monitoring message is *already* a tight binary structure — prefixes are bytes,
next-hops are bytes, AS-paths are arrays of integers. Re-encoding that into Protobuf means a schema
round-trip, descriptor lookups, and a second allocation of everything. So jBMP ships a hand-rolled,
length-prefixed binary codec: a one-byte presence bitmask for the optional extended families, then
just the fields that are present. No reflection, no schema registry, a single `byte[]` per message.

Is this the right call for every project? No — you lose schema evolution tooling, and you own the
forward-compatibility tests. But for a closed producer/consumer pair on the hot path, shaving the
serialization layer to the bone is free throughput. (jBMP versions the format and keeps the decoder
backward-compatible; that's the tax you pay for rolling your own.)

## Decision 3: bulk binary COPY into the database

The consumer's job is to get rows into PostgreSQL/TimescaleDB as fast as the disk allows. Per-row
`INSERT`s are a non-starter at these rates. jBMP renders each Kafka poll-batch directly into
PostgreSQL's **binary `COPY`** stream and streams it in one shot: `timestamptz` as microseconds,
`cidr`/`inet` in their native family-tagged form, AS-paths and communities as `int[]`/`text[]`,
the structured families as `jsonb`. The server ingests each value in its on-disk representation,
skipping the text-parse-and-validate it does for a normal `INSERT`.

Alongside the append-only history there's a *current-state* projection (`rib_state`): one row per
`(peer, prefix)`, kept up to date with an idempotent `INSERT … ON CONFLICT DO UPDATE` / `DELETE`.
That projection is rebuildable from the history, so it runs on a **single background worker off the
commit path** — the consumer commits its Kafka offsets the moment the history is durable and lets
the projection catch up behind it. Remember this detail; it comes back.

## Now the part where I was wrong three times

I built a benchmark — a mock pushing 50 routers × 10 peers × thousands of prefixes — and started
measuring the consumer's drain rate into the database. Here's where intuition failed.

### Wrong #1: "it's the CPU / the decode"

A Java Flight Recorder profile said otherwise. Out of an entire drain, there were only ~300 CPU
execution samples — the consumer was barely running Java code. It was *blocked*. Aggregating the
`jdk.SocketRead` events by remote port showed ~57 seconds of aggregate wait reading responses from
the **database**, and essentially nothing waiting on Kafka fetches. The bottleneck was I/O wait on
the DB round trips, not the parser, not the codec. First lesson: **profile before you optimise**;
the wide allocation-heavy decode I was sure would dominate was a rounding error.

### Wrong #2: "more parallelism will fix it"

When I scaled the mock up, throughput *collapsed* — big bursts then multi-second stalls. I assumed
a checkpoint storm and started tuning WAL and `synchronous_commit`. It changed nothing.

So I did the thing I should have done first: I took a **thread dump during a stall** and looked at
`pg_stat_activity` at the same instant. The database connections were almost all `idle`, waiting
on `ClientRead` — i.e. waiting for *my* client to send something. The bottleneck wasn't the DB at
all in that moment. And the thread dump showed three consumer threads stuck deep inside
`writeStats() → commit()`, blocked on a socket read for the commit response.

There it was. The low-volume statistics/peer writers were running **inline on the same threads that
do the route-monitor bulk `COPY`**. The mock generated a burst of stats; each was its own little
transaction; and the COPY threads that owned those partitions were head-of-line blocked behind
thousands of tiny per-message round trips. A reference design I looked at avoided this by giving
each topic-partition its own consumer goroutine — the per-message writes simply ran somewhere else.

The fix in Spring Kafka was to consume the low-volume topics on a **separate listener container**
with its own small thread pool, so a stats burst can never stall the bulk path. On the realistic
load, sustained drain went from ~17k rows/s to ~110k. Second lesson: **a thread dump taken during
the stall is worth a hundred guesses**, and "add threads" is not a strategy — *where* the work runs
matters more than how much of it there is.

### Wrong #3: "look how much faster mine is"

For a while my numbers looked spectacular — multiples faster than a comparable implementation on
the same hardware. Then I checked the database and found the comparison was a lie I'd told myself.

The Kafka partition key is the router identity. I had — "cleverly" — derived that identity from the
router's advertised system name, so my mock's 50 simulated routers fanned out across ~35 partitions
and 12 consumer threads. The implementation I was comparing against derived the identity from the
source IP; my mock's routers all shared one IP, so it collapsed to **one** partition and one
consumer. I wasn't measuring better code. I was measuring 12× the parallelism.

When I aligned the identity derivation (back to the source IP, which is also the faithful choice)
and re-ran at honest parity — same partitions, same full schema — the gap evaporated: ~19k vs ~19k
rows/s, within run-to-run noise. Third lesson, and the one I'd tattoo on a benchmark: **most
benchmark "wins" are configuration artifacts.** If your number is surprisingly good, the first
hypothesis should be that the test is unfair, not that you're a genius.

## Where it landed

jBMP sustains tens of thousands of rows/second per partition into a network-attached TimescaleDB
and scales near-linearly as traffic spreads across routers/partitions — hundreds of thousands of
rows/second in bursts across a few dozen partitions. The honest framing is that, per partition,
it's *on par* with a mature reference design while storing identical data — and it gets there with
plain blocking code on virtual threads, a hand-rolled binary wire format, and binary `COPY`. The
real ceiling, at parity, is the database's write path, not the JVM.

The three lessons generalise well beyond BMP:

1. **Profile before optimising** — your intuition about the hot path is probably wrong.
2. **During a stall, dump the threads and the DB sessions** — they'll tell you who's actually
   waiting on whom.
3. **Distrust a benchmark that flatters you** — equalise the configuration before you believe the
   number.

The code is open source (Apache-2.0). The boring blocking version, it turns out, is fast enough.
