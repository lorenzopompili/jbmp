package it.lpworks.jbmp.collector.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Externalised configuration for the jBMP collector, bound from the {@code jbmp.collector.*}
 * prefix.
 *
 * <p>The collector listens for BMP sessions over TCP (RFC 7854 §3.2) on {@link #bmpPort()},
 * accepting at most {@link #maxRouters()} concurrent router connections. Each connection is
 * served by one virtual thread that applies a per-read socket timeout of
 * {@link #readTimeout()} and publishes enriched messages to Kafka under the configured
 * {@link #topics()}. The {@link #collectorId()} is stamped into every published message's
 * provenance header so downstream consumers can attribute traffic to the originating
 * collector instance, and {@link #enabled()} gates the TCP listener so the application
 * context can be started (for example in tests) without binding a port.
 *
 * @param bmpPort     the TCP port the BMP listener binds to; defaults to {@code 1790}
 * @param maxRouters  the maximum number of concurrently connected routers; defaults to
 *                    {@code 1024}
 * @param readTimeout the per-read socket timeout applied to each router session; defaults to
 *                    {@code 5m}
 * @param collectorId the identifier stamped into every published message header; defaults to
 *                    {@code 0}
 * @param enabled     whether the TCP listener binds on application start; defaults to
 *                    {@code true}
 * @param topics      the destination Kafka topic names, one per enriched message type (never
 *                    {@code null})
 */
@ConfigurationProperties(prefix = "jbmp.collector")
public record CollectorProperties(
        @DefaultValue("1790") int bmpPort,
        @DefaultValue("1024") int maxRouters,
        @DefaultValue("5m") Duration readTimeout,
        @DefaultValue("0") int collectorId,
        @DefaultValue("true") boolean enabled,
        @DefaultValue Topics topics) {

    /**
     * Validates the numeric and temporal bounds and substitutes defaults for {@code null}
     * components so the record is always fully populated after binding.
     *
     * @throws IllegalArgumentException if {@code bmpPort} is outside {@code [0, 65535]},
     *                                  {@code maxRouters} is not positive, or
     *                                  {@code readTimeout} is not a positive duration
     */
    public CollectorProperties {
        if (bmpPort < 0 || bmpPort > 0xFFFF) {
            throw new IllegalArgumentException(
                    "bmpPort must be in [0, 65535] but was " + bmpPort);
        }
        if (maxRouters <= 0) {
            throw new IllegalArgumentException(
                    "maxRouters must be positive but was " + maxRouters);
        }
        if (readTimeout == null || readTimeout.isZero() || readTimeout.isNegative()) {
            throw new IllegalArgumentException(
                    "readTimeout must be a positive duration but was " + readTimeout);
        }
        if (topics == null) {
            topics = new Topics(null, null, null, null, null, null);
        }
    }

    /**
     * The set of Kafka topics the collector publishes to, one per enriched message type.
     *
     * <p>IPv4 and IPv6 route-monitoring traffic is split across two topics so that
     * high-volume IPv4 route churn does not delay IPv6 processing (and vice versa). The
     * {@link #raw()} topic carries the verbatim BMP message bytes for archival and
     * reprocessing.
     *
     * @param routeMonitorV4 the topic carrying encoded IPv4 {@code RouteMonitorMessage}s;
     *                       defaults to {@code bmp.route-monitor.v4}
     * @param routeMonitorV6 the topic carrying encoded IPv6 {@code RouteMonitorMessage}s;
     *                       defaults to {@code bmp.route-monitor.v6}
     * @param peerEvents     the topic carrying encoded {@code PeerEventMessage}s; defaults to
     *                       {@code bmp.peer-events}
     * @param stats          the topic carrying encoded {@code StatsReportMessage}s; defaults
     *                       to {@code bmp.stats}
     * @param routeMirror    the topic carrying encoded {@code RouteMirrorMessage}s; defaults
     *                       to {@code bmp.route-mirror}
     * @param raw            the topic carrying the verbatim raw BMP message bytes; defaults
     *                       to {@code bmp.raw}
     */
    public record Topics(
            @DefaultValue("bmp.route-monitor.v4") String routeMonitorV4,
            @DefaultValue("bmp.route-monitor.v6") String routeMonitorV6,
            @DefaultValue("bmp.peer-events") String peerEvents,
            @DefaultValue("bmp.stats") String stats,
            @DefaultValue("bmp.route-mirror") String routeMirror,
            @DefaultValue("bmp.raw") String raw) {

        /**
         * Substitutes the documented defaults for any {@code null} component so the record
         * is always fully populated after binding.
         */
        public Topics {
            if (routeMonitorV4 == null) {
                routeMonitorV4 = "bmp.route-monitor.v4";
            }
            if (routeMonitorV6 == null) {
                routeMonitorV6 = "bmp.route-monitor.v6";
            }
            if (peerEvents == null) {
                peerEvents = "bmp.peer-events";
            }
            if (stats == null) {
                stats = "bmp.stats";
            }
            if (routeMirror == null) {
                routeMirror = "bmp.route-mirror";
            }
            if (raw == null) {
                raw = "bmp.raw";
            }
        }
    }
}
