package it.lpworks.jbmp.consumer.kafka;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import it.lpworks.jbmp.consumer.TestMessages;
import it.lpworks.jbmp.consumer.batch.BatchAccumulator;
import it.lpworks.jbmp.consumer.config.ConsumerProperties;
import it.lpworks.jbmp.consumer.dump.DumpDetector;
import it.lpworks.jbmp.consumer.store.InMemoryStoreWriter;
import it.lpworks.jbmp.wire.WireCodec;

/**
 * Unit tests for {@link MessageDispatcher}: it decodes each topic's bytes with the correct
 * {@code WireCodec} method and routes the message to the batching engine or directly to the
 * store, committing single-message offsets immediately. Exercised entirely without Kafka.
 */
class MessageDispatcherTest {

    private static final UUID PEER = TestMessages.peer(1);

    private ConsumerProperties.Topics topics;
    private InMemoryStoreWriter store;
    private DumpDetector dumpDetector;
    private BatchAccumulator<String> accumulator;
    private List<String> committed;
    private List<String> singleCommits;
    private MessageDispatcher<String> dispatcher;

    @BeforeEach
    void setUp() {
        topics = new ConsumerProperties.Topics(
                "rm.v4", "rm.v6", "peers", "stats", "mirror");
        store = new InMemoryStoreWriter();
        dumpDetector = new DumpDetector();
        committed = new ArrayList<>();
        accumulator = new BatchAccumulator<>(store, 1000, Duration.ofSeconds(10),
                Clock.systemUTC(), committed::add);
        singleCommits = new ArrayList<>();
        dispatcher = new MessageDispatcher<>(topics, accumulator, dumpDetector, store);
    }

    private void dispatch(String topic, byte[] value, String token) {
        dispatcher.dispatch(topic, value, token, () -> singleCommits.add(token));
    }

    @Test
    void routeMonitorV4IsBatchedAndObservedForDump() {
        byte[] value = WireCodec.encodeRouteMonitor(TestMessages.announce(PEER, 1));

        dispatch("rm.v4", value, "t1");

        assertThat(accumulator.pending()).isEqualTo(1);
        assertThat(dumpDetector.isInDump(PEER)).isTrue();
        assertThat(singleCommits).isEmpty(); // route-monitor commit is owned by the batch flush
        assertThat(committed).isEmpty();
    }

    @Test
    void routeMonitorV6IsAlsoBatched() {
        byte[] value = WireCodec.encodeRouteMonitor(TestMessages.announce(PEER, 2));

        dispatch("rm.v6", value, "t1");

        assertThat(accumulator.pending()).isEqualTo(1);
    }

    @Test
    void peerEventIsWrittenAndCommittedImmediately() {
        byte[] value = WireCodec.encodePeerEvent(TestMessages.peerUp(PEER));

        dispatch("peers", value, "t1");

        assertThat(store.peerEvents()).hasSize(1);
        assertThat(singleCommits).containsExactly("t1");
    }

    @Test
    void statsReportIsWrittenAndCommittedImmediately() {
        byte[] value = WireCodec.encodeStatsReport(TestMessages.stats(PEER));

        dispatch("stats", value, "t1");

        assertThat(store.stats()).hasSize(1);
        assertThat(singleCommits).containsExactly("t1");
    }

    @Test
    void routeMirrorIsWrittenAndCommittedImmediately() {
        byte[] value = WireCodec.encodeRouteMirror(TestMessages.routeMirror(PEER));

        dispatch("mirror", value, "t1");

        assertThat(store.routeMirrors()).hasSize(1);
        assertThat(singleCommits).containsExactly("t1");
    }

    @Test
    void unknownTopicIsRejected() {
        byte[] value = WireCodec.encodeStatsReport(TestMessages.stats(PEER));

        assertThatThrownBy(() -> dispatch("unknown", value, "t1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unknown");
    }
}
