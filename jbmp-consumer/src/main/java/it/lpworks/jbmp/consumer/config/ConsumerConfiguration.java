package it.lpworks.jbmp.consumer.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the consumer's configuration properties.
 *
 * <p>{@link ConsumerProperties} is activated here via
 * {@link EnableConfigurationProperties} so that the {@code jbmp.consumer.*} prefix is bound
 * and available for injection throughout the module.
 *
 * <p>The parallel batch consumer commits offsets per poll (offset-after-write), so it needs
 * no scheduled time-flush tick and no shared {@link java.time.Clock}: the cross-poll
 * time-based flush that the legacy single-record {@link
 * it.lpworks.jbmp.consumer.batch.BatchAccumulator} relied on is unnecessary when each poll is
 * itself a write batch.
 */
@Configuration
@EnableConfigurationProperties(ConsumerProperties.class)
public class ConsumerConfiguration {
}
