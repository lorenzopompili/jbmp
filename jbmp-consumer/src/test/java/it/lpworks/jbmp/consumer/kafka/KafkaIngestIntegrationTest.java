package it.lpworks.jbmp.consumer.kafka;

import static org.awaitility.Awaitility.await;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.context.TestPropertySource;

import it.lpworks.jbmp.consumer.TestMessages;
import it.lpworks.jbmp.consumer.store.InMemoryStoreWriter;
import it.lpworks.jbmp.consumer.store.StoreWriter;
import it.lpworks.jbmp.wire.WireCodec;

/**
 * End-to-end test of the Kafka ingest path against an embedded broker.
 *
 * <p>It produces codec-encoded records to each consumer topic and asserts that the wired
 * {@link KafkaIngestService} -> {@link BatchRecordDispatcher} -> {@link InMemoryStoreWriter}
 * chain decodes and stores them: each poll batch is written and its offsets committed, so the
 * route-monitor historical rows are appended and the routing-state projection is populated. It
 * is tagged {@code integration} and therefore excluded from the default infrastructure-free
 * build.
 */
@Tag("integration")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@EmbeddedKafka(
        partitions = 1,
        bootstrapServersProperty = "spring.kafka.bootstrap-servers",
        topics = {"jbmp.route-monitor.v4", "jbmp.route-monitor.v6", "jbmp.peer-events",
                "jbmp.stats", "jbmp.route-mirror"})
@TestPropertySource(properties = {
        "spring.flyway.enabled=false",
        "spring.kafka.consumer.auto-offset-reset=earliest",
        "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
        "jbmp.consumer.group-id=jbmp-consumer-it",
        "jbmp.consumer.concurrency=1",
        "jbmp.consumer.batch-size=10"
})
class KafkaIngestIntegrationTest {

    /** Replaces the production store with a shared in-memory instance the test can inspect. */
    @TestConfiguration
    static class StoreOverride {
        @Bean
        @Primary
        InMemoryStoreWriter testStore() {
            return new InMemoryStoreWriter();
        }
    }

    @Autowired
    private EmbeddedKafkaBroker broker;

    @Autowired
    private StoreWriter storeWriter;

    private Producer<byte[], byte[]> newProducer() {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, broker.getBrokersAsString());
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class);
        return new KafkaProducer<>(props);
    }

    @Test
    void producedMessagesAreDecodedStoredAndBatchesFlush() {
        InMemoryStoreWriter store = (InMemoryStoreWriter) storeWriter;
        UUID peer = TestMessages.peer(1);

        try (Producer<byte[], byte[]> producer = newProducer()) {
            producer.send(new ProducerRecord<>("jbmp.route-monitor.v4", null,
                    WireCodec.encodeRouteMonitor(TestMessages.announce(peer, 1))));
            producer.send(new ProducerRecord<>("jbmp.route-monitor.v6", null,
                    WireCodec.encodeRouteMonitor(TestMessages.announce(peer, 2))));
            producer.send(new ProducerRecord<>("jbmp.peer-events", null,
                    WireCodec.encodePeerEvent(TestMessages.peerUp(peer))));
            producer.send(new ProducerRecord<>("jbmp.stats", null,
                    WireCodec.encodeStatsReport(TestMessages.stats(peer))));
            producer.send(new ProducerRecord<>("jbmp.route-mirror", null,
                    WireCodec.encodeRouteMirror(TestMessages.routeMirror(peer))));
            producer.flush();
        }

        // Single-message topics are written immediately on consumption.
        await().atMost(Duration.ofSeconds(30)).untilAsserted(() -> {
            assertThat(store.peerEvents()).hasSize(1);
            assertThat(store.stats()).hasSize(1);
            assertThat(store.routeMirrors()).hasSize(1);
        });

        // The two route-monitor records (IPv4 + IPv6) are consumed in their poll batch, which
        // appends the rows and projects routing state before its offsets are committed.
        await().atMost(Duration.ofSeconds(30)).untilAsserted(() -> {
            assertThat(store.routeMonitorRowCount()).isEqualTo(2);
            assertThat(store.ribState()).hasSize(2);
        });
    }
}
