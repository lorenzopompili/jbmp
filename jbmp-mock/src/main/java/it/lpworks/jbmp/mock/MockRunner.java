package it.lpworks.jbmp.mock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * Wires the {@link ScenarioGenerator} to the {@link TrafficSender} on application startup
 * and plays the configured scenario against the target collector.
 *
 * <p>The runner is guarded by {@code jbmp.mock.autostart} (default {@code true}). Tests
 * set it to {@code false} so loading the Spring context never opens a socket; the
 * generator and sender remain unit-testable in isolation.
 */
@Component
@ConditionalOnProperty(prefix = "jbmp.mock", name = "autostart", havingValue = "true",
        matchIfMissing = true)
public class MockRunner implements ApplicationRunner {

    private static final Logger LOG = LoggerFactory.getLogger(MockRunner.class);

    private final MockProperties properties;

    /**
     * Creates the runner with the bound configuration.
     *
     * @param properties the mock configuration
     * @throws NullPointerException if {@code properties} is {@code null}
     */
    public MockRunner(MockProperties properties) {
        this.properties = Objects.requireNonNull(properties, "properties");
    }

    /**
     * Builds the generator and sender from configuration and runs all router sessions.
     *
     * @param args the application arguments (unused)
     * @throws InterruptedException if interrupted while waiting for the sessions to finish
     */
    @Override
    public void run(ApplicationArguments args) throws InterruptedException {
        LOG.info("Starting jBMP mock: {} router(s), {} peer(s)/router, {} prefix(es)/peer, "
                        + "scenario '{}', target {}:{}, loop={}",
                properties.routers(), properties.peersPerRouter(), properties.prefixesPerPeer(),
                properties.resolvedScenario().id(), properties.targetHost(),
                properties.targetPort(), properties.loop());

        ScenarioGenerator generator = new ScenarioGenerator(properties);
        TrafficSender sender = new TrafficSender(properties, generator);
        sender.run();

        LOG.info("jBMP mock finished");
    }
}
