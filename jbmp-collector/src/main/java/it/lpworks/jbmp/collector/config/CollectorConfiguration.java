package it.lpworks.jbmp.collector.config;

import java.util.HashMap;
import java.util.Map;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

/**
 * Wires the collector's configuration properties and the byte-array Kafka producer used to
 * publish enriched messages.
 *
 * <p>{@link CollectorProperties} is activated via {@link EnableConfigurationProperties} so the
 * {@code jbmp.collector.*} prefix is bound and injectable. The producer is configured for raw
 * {@code byte[]} keys and values — keys are the 16-byte router identity, values are
 * {@link it.lpworks.jbmp.wire.WireCodec}-encoded DTOs — because the collector performs its own
 * serialisation and must control the partition key exactly.
 *
 * <p>The connection and tuning settings are read from the standard {@code spring.kafka.*}
 * namespace through the {@link Environment} (so this module does not need Spring Boot's Kafka
 * auto-configuration on the classpath). The serializers are forced to
 * {@link ByteArraySerializer} and throughput-oriented defaults — LZ4 compression, a 16&nbsp;KiB
 * batch size and a 5&nbsp;ms linger — are applied unless explicitly overridden under
 * {@code spring.kafka.producer.*}.
 */
@Configuration
@EnableConfigurationProperties(CollectorProperties.class)
public class CollectorConfiguration {

    /** Default bootstrap servers when {@code spring.kafka.bootstrap-servers} is unset. */
    private static final String DEFAULT_BOOTSTRAP_SERVERS = "localhost:9092";

    /** Producer batch size in bytes: 16&nbsp;KiB. */
    private static final String BATCH_SIZE = "16384";

    /** Producer linger in milliseconds. */
    private static final String LINGER_MS = "5";

    /** Producer compression codec. */
    private static final String COMPRESSION_TYPE = "lz4";

    /**
     * Builds the {@link ProducerFactory} for {@code byte[]} keys and values.
     *
     * <p>Connection settings come from {@code spring.kafka.bootstrap-servers}; the explicit
     * producer overrides come from {@code spring.kafka.producer.acks} and
     * {@code spring.kafka.producer.compression-type}/{@code batch-size} plus the
     * {@code spring.kafka.producer.properties.*} pass-through map. The key/value serializers
     * are always the byte-array serializer, and any unset throughput default is supplied here.
     *
     * @param environment the Spring environment exposing the {@code spring.kafka.*} properties
     * @return a producer factory yielding {@code byte[]}-keyed, {@code byte[]}-valued producers
     */
    @Bean
    public ProducerFactory<byte[], byte[]> bmpProducerFactory(Environment environment) {
        Map<String, Object> props = new HashMap<>();
        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, environment.getProperty(
                "spring.kafka.bootstrap-servers", DEFAULT_BOOTSTRAP_SERVERS));
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class);

        putIfPresent(environment, props, ProducerConfig.ACKS_CONFIG, "spring.kafka.producer.acks");
        putIfPresent(environment, props, ProducerConfig.CLIENT_ID_CONFIG,
                "spring.kafka.producer.client-id");

        // Throughput defaults, overridable via spring.kafka.producer.*.
        props.put(ProducerConfig.COMPRESSION_TYPE_CONFIG, environment.getProperty(
                "spring.kafka.producer.compression-type", COMPRESSION_TYPE));
        props.put(ProducerConfig.BATCH_SIZE_CONFIG, Integer.parseInt(environment.getProperty(
                "spring.kafka.producer.batch-size", BATCH_SIZE)));
        props.put(ProducerConfig.LINGER_MS_CONFIG, Integer.parseInt(environment.getProperty(
                "spring.kafka.producer.properties.linger.ms", LINGER_MS)));

        return new DefaultKafkaProducerFactory<>(props);
    }

    /**
     * Builds the {@link KafkaTemplate} the publisher uses to send encoded messages.
     *
     * @param bmpProducerFactory the byte-array producer factory
     * @return the byte-array Kafka template
     */
    @Bean
    public KafkaTemplate<byte[], byte[]> bmpKafkaTemplate(
            ProducerFactory<byte[], byte[]> bmpProducerFactory) {
        return new KafkaTemplate<>(bmpProducerFactory);
    }

    /**
     * Copies a property from the environment into the producer map only when it is present.
     *
     * @param environment the source environment
     * @param props       the destination producer property map
     * @param configKey   the Kafka {@link ProducerConfig} key
     * @param propertyKey the {@code spring.kafka.*} property name
     */
    private static void putIfPresent(Environment environment, Map<String, Object> props,
                                     String configKey, String propertyKey) {
        String value = environment.getProperty(propertyKey);
        if (value != null) {
            props.put(configKey, value);
        }
    }
}
