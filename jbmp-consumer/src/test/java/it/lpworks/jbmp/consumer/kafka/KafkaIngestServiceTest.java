package it.lpworks.jbmp.consumer.kafka;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.UUID;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.support.Acknowledgment;

import it.lpworks.jbmp.consumer.TestMessages;
import it.lpworks.jbmp.consumer.config.ConsumerProperties;
import it.lpworks.jbmp.consumer.dump.DumpDetector;
import it.lpworks.jbmp.consumer.kafka.BatchRecordDispatcherTest.RecordingStoreWriter;
import it.lpworks.jbmp.wire.WireCodec;

/**
 * Unit tests for {@link KafkaIngestService}: the batch listener acknowledges a poll only after
 * the dispatcher's writes succeed (offset-after-write), and withholds the acknowledgement when
 * a write throws so Kafka re-delivers the batch. The store-call ordering relative to the ack is
 * captured with a recording fake {@link org.springframework.kafka.support.Acknowledgment} and
 * the recording store from {@link BatchRecordDispatcherTest}. No Kafka broker is involved.
 */
class KafkaIngestServiceTest {

    private static final UUID PEER = TestMessages.peer(1);

    private ConsumerProperties.Topics topics;
    private RecordingStoreWriter store;
    private RecordingAck ack;
    private KafkaIngestService service;

    @BeforeEach
    void setUp() {
        topics = new ConsumerProperties.Topics("rm.v4", "rm.v6", "peers", "stats", "mirror");
        store = new RecordingStoreWriter();
        BatchRecordDispatcher dispatcher =
                new BatchRecordDispatcher(topics, new DumpDetector(), store, store::applyRibState);
        ack = new RecordingAck(store.callLog);
        service = new KafkaIngestService(dispatcher);
    }

    private static ConsumerRecord<byte[], byte[]> record(String topic, byte[] value) {
        return new ConsumerRecord<>(topic, 0, 0L, null, value);
    }

    @Test
    void acknowledgesOnlyAfterEveryWriteSucceeds() {
        List<ConsumerRecord<byte[], byte[]>> batch = List.of(
                record("rm.v4", WireCodec.encodeRouteMonitor(TestMessages.announce(PEER, 1))),
                record("peers", WireCodec.encodePeerEvent(TestMessages.peerUp(PEER))));

        service.onRouteMonitorBatch(batch, ack);

        // The acknowledgement is the very last action, strictly after both store writes.
        assertThat(store.callLog).containsExactly(
                "writePeerEvent", "writeRouteMonitorBatch", "applyRibState", "acknowledge");
        assertThat(ack.acknowledged).isTrue();
    }

    @Test
    void withholdsAcknowledgementWhenAWriteThrows() {
        store.failRouteMonitorWrite = true;
        List<ConsumerRecord<byte[], byte[]>> batch = List.of(
                record("rm.v4", WireCodec.encodeRouteMonitor(TestMessages.announce(PEER, 1))));

        assertThatThrownBy(() -> service.onRouteMonitorBatch(batch, ack))
                .isInstanceOf(IllegalStateException.class);

        // The write failed, so the offsets are never committed: Kafka will re-deliver.
        assertThat(ack.acknowledged).isFalse();
        assertThat(store.callLog).doesNotContain("acknowledge");
    }

    @Test
    void acknowledgesAnEmptyPollWithoutWriting() {
        service.onRouteMonitorBatch(List.of(), ack);

        assertThat(ack.acknowledged).isTrue();
        assertThat(store.callLog).containsExactly("acknowledge");
    }

    /** An {@link Acknowledgment} that records when it is acknowledged into a shared call log. */
    private static final class RecordingAck implements Acknowledgment {
        private final List<String> callLog;
        boolean acknowledged;

        RecordingAck(List<String> callLog) {
            this.callLog = callLog;
        }

        @Override
        public void acknowledge() {
            acknowledged = true;
            callLog.add("acknowledge");
        }
    }
}
