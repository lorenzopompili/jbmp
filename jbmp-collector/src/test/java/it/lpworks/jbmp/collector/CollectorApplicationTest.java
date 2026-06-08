package it.lpworks.jbmp.collector;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import it.lpworks.jbmp.collector.enrich.BmpEnricher;
import it.lpworks.jbmp.collector.publish.BmpMessagePublisher;
import it.lpworks.jbmp.collector.server.BmpServer;

/**
 * Smoke test that the full collector application context loads.
 *
 * <p>The TCP listener is disabled via {@code jbmp.collector.enabled=false} so no port is
 * bound, and Kafka producer beans connect lazily (a {@code KafkaTemplate} establishes its
 * producer only on first send), so the context starts without an external broker. This test
 * therefore runs in the default (non-integration) build.
 */
@SpringBootTest(properties = {
        "jbmp.collector.enabled=false",
        "spring.kafka.bootstrap-servers=localhost:9092"
})
class CollectorApplicationTest {

    @Autowired
    private BmpEnricher enricher;

    @Autowired
    private BmpMessagePublisher publisher;

    @Autowired
    private BmpServer server;

    @Test
    void contextLoads() {
        assertThat(enricher).isNotNull();
        assertThat(publisher).isNotNull();
        assertThat(server).isNotNull();
        // The listener must not have bound a port while disabled.
        assertThat(server.boundPort()).isEqualTo(-1);
    }
}
