package it.lpworks.jbmp.collector.publish;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;
import java.util.OptionalLong;
import java.util.UUID;

import org.apache.kafka.clients.consumer.Consumer;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.test.EmbeddedKafkaBroker;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.kafka.test.utils.KafkaTestUtils;

import it.lpworks.jbmp.collector.config.CollectorProperties;
import it.lpworks.jbmp.collector.metrics.CollectorMetrics;
import it.lpworks.jbmp.identity.UuidFactory;
import it.lpworks.jbmp.wire.MessageHeader;
import it.lpworks.jbmp.wire.RouteAction;
import it.lpworks.jbmp.wire.RouteMonitorMessage;
import it.lpworks.jbmp.wire.WireCodec;

/**
 * Integration test for {@link KafkaBmpMessagePublisher} against an in-process embedded Kafka
 * broker (spring-kafka-test). It verifies that a route-monitor message is produced to the
 * IPv4 topic, keyed by the 16-byte router identity, with a {@link WireCodec}-decodable value.
 *
 * <p>Tagged {@code integration} so it is excluded from the default infrastructure-free build.
 */
@Tag("integration")
@EmbeddedKafka(topics = {"bmp.route-monitor.v4"}, partitions = 1)
class KafkaBmpMessagePublisherIntegrationTest {

    private static final byte[] ROUTER_IP = {10, 0, 0, 1};

    private DefaultKafkaProducerFactory<byte[], byte[]> producerFactory;
    private Consumer<byte[], byte[]> consumer;

    @AfterEach
    void tearDown() {
        if (consumer != null) {
            consumer.close();
        }
        if (producerFactory != null) {
            producerFactory.destroy();
        }
    }

    @Test
    void publishesRouteMonitorKeyedByRouterId(EmbeddedKafkaBroker broker) {
        String bootstrap = broker.getBrokersAsString();

        producerFactory = new DefaultKafkaProducerFactory<>(Map.of(
                org.apache.kafka.clients.producer.ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap,
                org.apache.kafka.clients.producer.ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG,
                org.apache.kafka.common.serialization.ByteArraySerializer.class,
                org.apache.kafka.clients.producer.ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,
                org.apache.kafka.common.serialization.ByteArraySerializer.class));
        KafkaTemplate<byte[], byte[]> template = new KafkaTemplate<>(producerFactory);

        CollectorProperties properties = new CollectorProperties(
                0, 1024, Duration.ofSeconds(30), 3, true, null);
        CollectorMetrics metrics = new CollectorMetrics(new SimpleMeterRegistry());
        KafkaBmpMessagePublisher publisher =
                new KafkaBmpMessagePublisher(template, properties, metrics);

        UUID routerId = UuidFactory.router(ROUTER_IP);
        UUID peerId = UuidFactory.peer(routerId, new byte[]{(byte) 192, 0, 2, 1}, 65001, "");
        RouteMonitorMessage message = sampleRouteMonitor(routerId, peerId);

        publisher.publishRouteMonitor(message);
        template.flush();

        // Subscribe a consumer to the v4 topic and read back the single record.
        Map<String, Object> consumerProps =
                KafkaTestUtils.consumerProps(bootstrap, "it-group", "true");
        consumer = new DefaultKafkaConsumerFactory<>(consumerProps,
                new ByteArrayDeserializer(), new ByteArrayDeserializer())
                .createConsumer();
        broker.consumeFromAnEmbeddedTopic(consumer, "bmp.route-monitor.v4");

        ConsumerRecord<byte[], byte[]> record =
                KafkaTestUtils.getSingleRecord(consumer, "bmp.route-monitor.v4",
                        Duration.ofSeconds(10));

        assertThat(record.key()).isEqualTo(uuidBytes(routerId));
        RouteMonitorMessage decoded = WireCodec.decodeRouteMonitor(record.value());
        assertThat(decoded).isEqualTo(message);
        assertThat(decoded.header().routerId()).isEqualTo(routerId);
    }

    private static RouteMonitorMessage sampleRouteMonitor(UUID routerId, UUID peerId) {
        MessageHeader header = new MessageHeader(
                1_700_000_000_000_000_000L, 1_700_000_000_500_000_000L, 3, routerId, peerId);
        return new RouteMonitorMessage(
                header, RouteAction.ANNOUNCE, true, false, true, false, false,
                new byte[]{(byte) 198, 51, 100, 0}, 24,
                OptionalLong.empty(), OptionalLong.of(64500),
                new long[]{65001, 64500}, java.util.List.of(),
                new byte[]{(byte) 192, 0, 2, (byte) 254},
                OptionalLong.empty(), OptionalLong.of(100), 0, false,
                OptionalLong.empty(), new byte[0], new int[0],
                java.util.List.of(), java.util.List.of(), java.util.Optional.empty(),
                java.util.List.of(), "", 0, java.util.List.of(), new long[0],
                new byte[0], new byte[0], new byte[0], new byte[0], new byte[0]);
    }

    private static byte[] uuidBytes(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (msb >>> (56 - 8 * i));
            out[8 + i] = (byte) (lsb >>> (56 - 8 * i));
        }
        return out;
    }
}
