package it.lpworks.jbmp.consumer.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ConsumerProperties}: default substitution, validation of the size and
 * interval bounds, and the route-monitor topic classification.
 */
class ConsumerPropertiesTest {

    @Test
    void defaultsAreApplied() {
        ConsumerProperties props =
                new ConsumerProperties(50000, 12, Duration.ofMillis(500), "", null);

        assertThat(props.batchSize()).isEqualTo(50000);
        assertThat(props.concurrency()).isEqualTo(12);
        assertThat(props.flushInterval()).isEqualTo(Duration.ofMillis(500));
        assertThat(props.topics().routeMonitorV4()).isEqualTo("jbmp.route-monitor.v4");
        assertThat(props.topics().routeMonitorV6()).isEqualTo("jbmp.route-monitor.v6");
        assertThat(props.topics().peerEvents()).isEqualTo("jbmp.peer-events");
        assertThat(props.topics().stats()).isEqualTo("jbmp.stats");
        assertThat(props.topics().routeMirror()).isEqualTo("jbmp.route-mirror");
    }

    @Test
    void rejectsNonPositiveBatchSize() {
        assertThatThrownBy(() -> new ConsumerProperties(0, 12, Duration.ofMillis(1), "", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonPositiveConcurrency() {
        assertThatThrownBy(() -> new ConsumerProperties(1, 0, Duration.ofMillis(1), "", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ConsumerProperties(1, -1, Duration.ofMillis(1), "", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonPositiveFlushInterval() {
        assertThatThrownBy(() -> new ConsumerProperties(1, 12, Duration.ZERO, "", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ConsumerProperties(1, 12, Duration.ofMillis(-1), "", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void isRouteMonitorMatchesBothFamiliesOnly() {
        ConsumerProperties.Topics topics =
                new ConsumerProperties.Topics("v4", "v6", "peers", "stats", "mirror");

        assertThat(topics.isRouteMonitor("v4")).isTrue();
        assertThat(topics.isRouteMonitor("v6")).isTrue();
        assertThat(topics.isRouteMonitor("peers")).isFalse();
        assertThat(topics.isRouteMonitor("stats")).isFalse();
        assertThat(topics.isRouteMonitor(null)).isFalse();
    }
}
