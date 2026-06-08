package it.lpworks.jbmp.consumer.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Externalised configuration for the jBMP consumer, bound from the {@code jbmp.consumer.*}
 * prefix.
 *
 * <p>The consumer runs a {@link #concurrency()}-way parallel batch listener: each container
 * thread polls its own assigned partitions, decodes a whole poll batch (up to {@link
 * #batchSize()} records, used as the Kafka {@code max.poll.records}) and writes it to the
 * {@link it.lpworks.jbmp.consumer.store.StoreWriter store} before committing the batch's
 * offsets. Kafka offsets are therefore committed only after a batch has been durably written
 * (the offset-after-write guarantee), and the {@code N} container threads write independently
 * with no shared mutable buffer.
 *
 * @param batchSize     the Kafka {@code max.poll.records}: the maximum number of records a
 *                      single poll returns and thus the upper bound on one write batch;
 *                      defaults to {@code 50000}
 * @param concurrency   the number of parallel listener container threads (partition
 *                      consumers); defaults to {@code 12} and must be positive
 * @param flushInterval the maximum age of an open batch before a time-triggered flush,
 *                      retained for the legacy {@link
 *                      it.lpworks.jbmp.consumer.batch.BatchAccumulator}; defaults to {@code
 *                      500ms}
 * @param groupId       the Kafka consumer group identifier the listeners join; when blank
 *                      the Spring Kafka {@code spring.kafka.consumer.group-id} value applies
 * @param topics        the source topic names, which must match those the collector
 *                      publishes to (never {@code null})
 */
@ConfigurationProperties(prefix = "jbmp.consumer")
public record ConsumerProperties(
        @DefaultValue("50000") int batchSize,
        @DefaultValue("12") int concurrency,
        @DefaultValue("500ms") Duration flushInterval,
        @DefaultValue("") String groupId,
        @DefaultValue Topics topics) {

    /**
     * Validates the numeric and temporal bounds and substitutes defaults for {@code null}
     * components so the record is always fully populated after binding.
     *
     * @throws IllegalArgumentException if {@code batchSize} or {@code concurrency} is not
     *                                  positive, or {@code flushInterval} is not positive
     */
    public ConsumerProperties {
        if (batchSize <= 0) {
            throw new IllegalArgumentException("batchSize must be positive but was " + batchSize);
        }
        if (concurrency <= 0) {
            throw new IllegalArgumentException(
                    "concurrency must be positive but was " + concurrency);
        }
        if (flushInterval == null || flushInterval.isZero() || flushInterval.isNegative()) {
            throw new IllegalArgumentException(
                    "flushInterval must be a positive duration but was " + flushInterval);
        }
        if (groupId == null) {
            groupId = "";
        }
        if (topics == null) {
            topics = new Topics(null, null, null, null, null);
        }
    }

    /**
     * The set of Kafka topics the consumer subscribes to, one per enriched message type.
     *
     * <p>These names mirror the collector's producer-side topic configuration. IPv4 and
     * IPv6 route-monitoring traffic is split across two topics so that high-volume IPv4
     * route churn does not delay IPv6 processing (and vice versa); both feed the same
     * decode-and-batch path.
     *
     * @param routeMonitorV4 the topic carrying encoded IPv4 {@code RouteMonitorMessage}s
     * @param routeMonitorV6 the topic carrying encoded IPv6 {@code RouteMonitorMessage}s
     * @param peerEvents     the topic carrying encoded {@code PeerEventMessage}s
     * @param stats          the topic carrying encoded {@code StatsReportMessage}s
     * @param routeMirror    the topic carrying encoded {@code RouteMirrorMessage}s
     */
    public record Topics(
            @DefaultValue("jbmp.route-monitor.v4") String routeMonitorV4,
            @DefaultValue("jbmp.route-monitor.v6") String routeMonitorV6,
            @DefaultValue("jbmp.peer-events") String peerEvents,
            @DefaultValue("jbmp.stats") String stats,
            @DefaultValue("jbmp.route-mirror") String routeMirror) {

        /**
         * Substitutes the documented defaults for any {@code null} component so the record
         * is always fully populated after binding.
         */
        public Topics {
            if (routeMonitorV4 == null) {
                routeMonitorV4 = "jbmp.route-monitor.v4";
            }
            if (routeMonitorV6 == null) {
                routeMonitorV6 = "jbmp.route-monitor.v6";
            }
            if (peerEvents == null) {
                peerEvents = "jbmp.peer-events";
            }
            if (stats == null) {
                stats = "jbmp.stats";
            }
            if (routeMirror == null) {
                routeMirror = "jbmp.route-mirror";
            }
        }

        /**
         * Returns whether the supplied topic is one of the two route-monitoring topics.
         *
         * @param topic the topic name to test (may be {@code null})
         * @return {@code true} if {@code topic} is the IPv4 or IPv6 route-monitor topic
         */
        public boolean isRouteMonitor(String topic) {
            return routeMonitorV4.equals(topic) || routeMonitorV6.equals(topic);
        }
    }
}
