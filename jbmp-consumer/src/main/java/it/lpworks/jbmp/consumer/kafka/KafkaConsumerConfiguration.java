package it.lpworks.jbmp.consumer.kafka;

import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.serialization.ByteArrayDeserializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;
import org.springframework.kafka.listener.ContainerProperties.AckMode;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.util.StringUtils;

import it.lpworks.jbmp.consumer.config.ConsumerProperties;
import it.lpworks.jbmp.consumer.dump.DumpDetector;
import it.lpworks.jbmp.consumer.store.RibStateWorker;
import it.lpworks.jbmp.consumer.store.StoreWriter;

/**
 * Kafka infrastructure beans for the parallel batch consumer: a {@code byte[]}/{@code byte[]}
 * consumer factory with aggressive fetch tuning, an {@code N}-way concurrent batch-listener
 * container factory in manual-acknowledgement mode, and the stateless {@link
 * BatchRecordDispatcher} that decodes and writes each poll.
 *
 * <p>The consumer client settings are read directly from the standard {@code spring.kafka.*}
 * environment keys rather than from Spring Boot's Kafka auto-configuration, so the wiring is
 * self-contained and does not require the optional Boot Kafka module to be present.
 *
 * <p>The offset token is the per-poll {@link Acknowledgment}: {@link KafkaIngestService}
 * acknowledges a batch only after its store writes succeed, giving the offset-after-write
 * guarantee. Each of the {@code concurrency} container threads polls its own partitions and
 * writes independently, with no shared mutable buffer.
 */
@Configuration
@EnableKafka
public class KafkaConsumerConfiguration {

    private static final String DEFAULT_BOOTSTRAP_SERVERS = "localhost:9092";
    private static final String DEFAULT_AUTO_OFFSET_RESET = "earliest";

    /**
     * Pending route-monitor batches buffered for the asynchronous {@code rib_state} projection
     * before the oldest is dropped (the projection stays rebuildable from the history).
     */
    private static final int RIB_STATE_QUEUE_DEPTH = 64;

    /**
     * Builds a {@code byte[]} key / {@code byte[]} value consumer factory from the standard
     * {@code spring.kafka.*} environment properties, fixing the deserializers to {@link
     * ByteArrayDeserializer}, disabling auto-commit (offsets are committed only via manual
     * acknowledgement) and applying the consumer group id (preferring {@code
     * jbmp.consumer.group-id} when set, otherwise {@code spring.kafka.consumer.group-id}).
     *
     * <p>It sets only {@code max.poll.records} = {@link ConsumerProperties#batchSize()} so a
     * full configured batch is delivered per poll; every other fetch parameter stays at the
     * Kafka client default. Throughput comes from the parallel batch architecture and the
     * binary COPY write path, not from client-specific tuning.
     *
     * @param environment        the Spring environment carrying the {@code spring.kafka.*}
     *                           properties
     * @param consumerProperties the bound {@code jbmp.consumer} properties
     * @return a byte-array consumer factory
     */
    @Bean
    public ConsumerFactory<byte[], byte[]> byteArrayConsumerFactory(
            Environment environment, ConsumerProperties consumerProperties) {
        Map<String, Object> props = new HashMap<>();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, environment.getProperty(
                "spring.kafka.bootstrap-servers", DEFAULT_BOOTSTRAP_SERVERS));
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, environment.getProperty(
                "spring.kafka.consumer.auto-offset-reset", DEFAULT_AUTO_OFFSET_RESET));
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, ByteArrayDeserializer.class);
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);

        // Deliver a full configured batch per poll (mirrors batch_size); every other fetch
        // parameter stays at the Kafka client default so the consumer runs under the same
        // configuration as the reference implementation.
        props.put(ConsumerConfig.MAX_POLL_RECORDS_CONFIG, consumerProperties.batchSize());

        String groupId = StringUtils.hasText(consumerProperties.groupId())
                ? consumerProperties.groupId()
                : environment.getProperty("spring.kafka.consumer.group-id");
        if (StringUtils.hasText(groupId)) {
            props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        }
        return new DefaultKafkaConsumerFactory<>(props);
    }

    /**
     * The listener container factory used by {@link KafkaIngestService}: a {@code
     * concurrency}-way concurrent, batch-mode container in manual-acknowledgement mode over the
     * byte-array consumer factory.
     *
     * <p>{@code setConcurrency} runs one polling thread per configured value (capped by the
     * partition count at runtime), {@code setBatchListener(true)} delivers a whole poll as a
     * {@code List<ConsumerRecord>} rather than record-by-record, and {@link AckMode#MANUAL}
     * leaves the offset commit to the listener so it can be tied to a successful write.
     *
     * @param consumerFactory    the byte-array consumer factory
     * @param consumerProperties the bound {@code jbmp.consumer} properties
     * @return a concurrent batch manual-ack container factory
     */
    @Bean
    public ConcurrentKafkaListenerContainerFactory<byte[], byte[]> byteArrayKafkaListenerContainerFactory(
            ConsumerFactory<byte[], byte[]> consumerFactory,
            ConsumerProperties consumerProperties) {
        ConcurrentKafkaListenerContainerFactory<byte[], byte[]> factory =
                new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory);
        factory.setConcurrency(consumerProperties.concurrency());
        factory.setBatchListener(true);
        factory.getContainerProperties().setAckMode(AckMode.MANUAL);
        return factory;
    }

    /**
     * The stateless per-poll decode-and-write core shared by the batch listener.
     *
     * @param consumerProperties the bound {@code jbmp.consumer} properties
     * @param dumpDetector       the per-peer initial-dump tracker
     * @param store              the persistence sink
     * @return the configured batch dispatcher
     */
    /**
     * The asynchronous {@code rib_state} projection worker. It decouples the rebuildable
     * current-state upserts from the offset-commit path so the historical bulk COPY is not
     * serialised behind thousands of per-poll upserts. Closed on context shutdown to drain.
     *
     * @param store the persistence sink
     * @return the started rib-state worker
     */
    @Bean(destroyMethod = "close")
    public RibStateWorker ribStateWorker(StoreWriter store) {
        return new RibStateWorker(store, RIB_STATE_QUEUE_DEPTH);
    }

    /**
     * The stateless per-poll decode-and-write core shared by the batch listener. The historical
     * route-monitor batch is written synchronously (offset-after-write); the {@code rib_state}
     * projection is handed to {@link RibStateWorker} to run off the commit path.
     *
     * @param consumerProperties the bound {@code jbmp.consumer} properties
     * @param dumpDetector       the per-peer initial-dump tracker
     * @param store              the persistence sink
     * @param ribStateWorker     the asynchronous rib-state projection worker
     * @return the configured batch dispatcher
     */
    @Bean
    public BatchRecordDispatcher batchRecordDispatcher(ConsumerProperties consumerProperties,
            DumpDetector dumpDetector, StoreWriter store, RibStateWorker ribStateWorker) {
        return new BatchRecordDispatcher(consumerProperties.topics(), dumpDetector, store,
                ribStateWorker::submit);
    }

    /**
     * The per-peer initial-dump tracker bean.
     *
     * @return a fresh dump detector
     */
    @Bean
    public DumpDetector dumpDetector() {
        return new DumpDetector();
    }
}
