package it.lpworks.jbmp.consumer.batch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import it.lpworks.jbmp.consumer.TestMessages;
import it.lpworks.jbmp.consumer.store.InMemoryStoreWriter;
import it.lpworks.jbmp.consumer.store.RibKey;
import it.lpworks.jbmp.consumer.store.StoreWriter;
import it.lpworks.jbmp.wire.PeerEventMessage;
import it.lpworks.jbmp.wire.RouteMirrorMessage;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.StatsReportMessage;

/**
 * Unit tests for {@link BatchAccumulator}: size- and time-triggered flushes, the
 * offset-after-write guarantee in both success and failure cases, and the announce/withdraw
 * routing-state projection. Time is controlled with an adjustable {@link Clock}; there is no
 * real sleeping and no Kafka.
 */
class BatchAccumulatorTest {

    private static final UUID PEER = TestMessages.peer(1);

    /** A clock whose instant the test moves forward explicitly. */
    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2025-01-01T00:00:00Z");

        @Override
        public Instant instant() {
            return now;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    private MutableClock clock;
    private InMemoryStoreWriter store;
    private List<String> committedTokens;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        store = new InMemoryStoreWriter();
        committedTokens = new ArrayList<>();
    }

    private BatchAccumulator<String> newAccumulator(int batchSize, Duration flushInterval) {
        return new BatchAccumulator<>(store, batchSize, flushInterval, clock,
                committedTokens::add);
    }

    @Test
    void flushesWhenBatchSizeReached() {
        BatchAccumulator<String> acc = newAccumulator(3, Duration.ofSeconds(10));

        acc.add(TestMessages.announce(PEER, 1), "t1");
        acc.add(TestMessages.announce(PEER, 2), "t2");
        assertThat(store.routeMonitorBatches()).isEmpty();
        assertThat(committedTokens).isEmpty();

        acc.add(TestMessages.announce(PEER, 3), "t3"); // reaches batchSize -> flush

        assertThat(store.routeMonitorBatches()).hasSize(1);
        assertThat(store.routeMonitorRowCount()).isEqualTo(3);
        assertThat(acc.pending()).isZero();
        assertThat(committedTokens).containsExactly("t3"); // last token of the batch
    }

    @Test
    void flushesWhenFlushIntervalElapsesOnTick() {
        BatchAccumulator<String> acc = newAccumulator(1000, Duration.ofMillis(500));

        acc.add(TestMessages.announce(PEER, 1), "t1");
        assertThat(acc.tick()).isFalse(); // not yet overdue
        assertThat(store.routeMonitorBatches()).isEmpty();

        clock.advance(Duration.ofMillis(500)); // exactly the interval -> overdue
        assertThat(acc.tick()).isTrue();

        assertThat(store.routeMonitorBatches()).hasSize(1);
        assertThat(store.routeMonitorRowCount()).isEqualTo(1);
        assertThat(committedTokens).containsExactly("t1");
    }

    @Test
    void tickOnEmptyBufferDoesNothing() {
        BatchAccumulator<String> acc = newAccumulator(10, Duration.ofMillis(1));
        clock.advance(Duration.ofSeconds(5));
        assertThat(acc.tick()).isFalse();
        assertThat(store.routeMonitorBatches()).isEmpty();
        assertThat(committedTokens).isEmpty();
    }

    @Test
    void lateArrivingRecordFlushesOverdueBatchFirst() {
        BatchAccumulator<String> acc = newAccumulator(1000, Duration.ofMillis(500));

        acc.add(TestMessages.announce(PEER, 1), "t1");
        clock.advance(Duration.ofSeconds(1)); // batch is now overdue

        acc.add(TestMessages.announce(PEER, 2), "t2"); // should flush the first, then buffer

        assertThat(store.routeMonitorBatches()).hasSize(1);
        assertThat(store.routeMonitorBatches().get(0)).hasSize(1);
        assertThat(committedTokens).containsExactly("t1");
        assertThat(acc.pending()).isEqualTo(1); // the late record is buffered for the next flush
    }

    @Test
    void offsetCommittedOnlyAfterSuccessfulWrite() {
        BatchAccumulator<String> acc = newAccumulator(2, Duration.ofSeconds(10));
        acc.add(TestMessages.announce(PEER, 1), "t1");

        // Before the flush, nothing is written and no offset is committed.
        assertThat(store.routeMonitorBatches()).isEmpty();
        assertThat(committedTokens).isEmpty();

        acc.add(TestMessages.announce(PEER, 2), "t2"); // triggers a successful flush

        assertThat(store.routeMonitorRowCount()).isEqualTo(2);
        assertThat(committedTokens).containsExactly("t2");
    }

    @Test
    void offsetNotCommittedWhenWriterThrowsAndStateIsRetained() {
        AtomicReference<RuntimeException> toThrow = new AtomicReference<>();
        StoreWriter failing = new StoreWriter() {
            @Override
            public void writeRouteMonitorBatch(List<RouteMonitorMessage> batch) {
                RuntimeException ex = toThrow.get();
                if (ex != null) {
                    throw ex;
                }
                store.writeRouteMonitorBatch(batch);
            }

            @Override
            public void applyRibState(List<RouteMonitorMessage> batch) {
                store.applyRibState(batch);
            }

            @Override
            public void writePeerEvent(PeerEventMessage event) {
                store.writePeerEvent(event);
            }

            @Override
            public void writeStats(StatsReportMessage stats) {
                store.writeStats(stats);
            }

            @Override
            public void writeRouteMirror(RouteMirrorMessage mirror) {
                store.writeRouteMirror(mirror);
            }
        };
        BatchAccumulator<String> acc =
                new BatchAccumulator<>(failing, 2, Duration.ofSeconds(10), clock,
                        committedTokens::add);

        toThrow.set(new IllegalStateException("store unavailable"));
        acc.add(TestMessages.announce(PEER, 1), "t1");

        // The size-triggered flush throws; the offset is withheld and the buffer is retained.
        assertThatThrownBy(() -> acc.add(TestMessages.announce(PEER, 2), "t2"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("store unavailable");
        assertThat(committedTokens).isEmpty();
        assertThat(acc.pending()).isEqualTo(2);
        assertThat(store.routeMonitorBatches()).isEmpty();

        // When the store recovers, an explicit flush succeeds and now commits the offset.
        toThrow.set(null);
        acc.flush();
        assertThat(store.routeMonitorRowCount()).isEqualTo(2);
        assertThat(committedTokens).containsExactly("t2");
    }

    @Test
    void ribStateProjectsAnnouncesAndWithdraws() {
        BatchAccumulator<String> acc = newAccumulator(100, Duration.ofSeconds(10));

        acc.add(TestMessages.announce(PEER, 1), "t1");
        acc.add(TestMessages.announce(PEER, 2), "t2");
        acc.add(TestMessages.withdraw(PEER, 1), "t3"); // removes route 1
        acc.flush();

        var rib = store.ribState();
        assertThat(rib).hasSize(1);
        RibKey remaining = rib.keySet().iterator().next();
        assertThat(remaining.peerId()).isEqualTo(PEER);
        assertThat(remaining.prefix()).containsExactly(10, 0, 2, 0);
        assertThat(committedTokens).containsExactly("t3");
    }

    @Test
    void endOfRibMarkerDoesNotAlterRibState() {
        BatchAccumulator<String> acc = newAccumulator(100, Duration.ofSeconds(10));

        acc.add(TestMessages.announce(PEER, 5), "t1");
        acc.add(TestMessages.endOfRib(PEER), "t2"); // no NLRI -> no state change
        acc.flush();

        assertThat(store.ribState()).hasSize(1);
        assertThat(committedTokens).containsExactly("t2");
    }

    @Test
    void constructorRejectsInvalidArguments() {
        assertThatThrownBy(() -> newAccumulator(0, Duration.ofSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> newAccumulator(1, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
