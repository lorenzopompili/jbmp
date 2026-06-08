package it.lpworks.jbmp.mock;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the BMP traffic generator, bound from the {@code jbmp.mock.*}
 * namespace.
 *
 * <p>The generator opens one TCP session per simulated router to a collector and
 * emits an RFC 7854 message stream: an Initiation message, a Peer Up Notification per
 * monitored peer, an initial table dump of Route Monitoring announcements followed by
 * an End-of-RIB marker (RFC 4724) per peer, a Statistics Report per peer, and — when a
 * churn rate is configured — periodic incremental announce/withdraw updates.
 *
 * @param targetHost                  the collector host to connect to
 * @param targetPort                  the collector TCP port (the BMP IANA port is 1790)
 * @param routers                     the number of simulated routers (one session each)
 * @param peersPerRouter              the number of monitored peers advertised per router
 * @param prefixesPerPeer             the number of prefixes in each peer's initial dump
 * @param scenario                    the scenario name (see {@link Scenario})
 * @param incrementalUpdatesPerSecond the post-dump churn rate, in updates per second;
 *                                    {@code 0} disables incremental churn
 * @param loop                        whether to restart the whole scenario after it ends
 * @param autostart                   whether the {@link MockRunner} runs on startup;
 *                                    set {@code false} under test to keep the context inert
 */
@ConfigurationProperties("jbmp.mock")
public record MockProperties(
        String targetHost,
        int targetPort,
        int routers,
        int peersPerRouter,
        int prefixesPerPeer,
        String scenario,
        int incrementalUpdatesPerSecond,
        boolean loop,
        boolean autostart) {

    /** The IANA-assigned default BMP port (RFC 7854 §3.2). */
    private static final int DEFAULT_PORT = 1790;

    /**
     * Applies the documented defaults to any unset (zero / blank / {@code null}) field.
     *
     * <p>Spring binds a record's components positionally; absent properties arrive as
     * {@code 0}, {@code false} or {@code null}, so the canonical constructor substitutes
     * sensible defaults and resolves the scenario name. {@code autostart} cannot have a
     * non-{@code false} default applied here without losing the explicit {@code false}
     * a test profile sets, so its default is supplied at the property layer
     * ({@code application.yml}) instead.
     */
    public MockProperties {
        targetHost = (targetHost == null || targetHost.isBlank()) ? "localhost" : targetHost;
        targetPort = targetPort <= 0 ? DEFAULT_PORT : targetPort;
        routers = routers <= 0 ? 1 : routers;
        peersPerRouter = peersPerRouter <= 0 ? 2 : peersPerRouter;
        prefixesPerPeer = prefixesPerPeer < 0 ? 0 : (prefixesPerPeer == 0 ? 1000 : prefixesPerPeer);
        scenario = (scenario == null || scenario.isBlank()) ? Scenario.INITIAL_DUMP.id() : scenario;
        incrementalUpdatesPerSecond = Math.max(0, incrementalUpdatesPerSecond);
    }

    /**
     * Resolves the configured {@link Scenario}.
     *
     * @return the matching scenario, defaulting to {@link Scenario#INITIAL_DUMP} when
     *         the configured name is unrecognised
     */
    public Scenario resolvedScenario() {
        return Scenario.fromId(scenario);
    }
}
