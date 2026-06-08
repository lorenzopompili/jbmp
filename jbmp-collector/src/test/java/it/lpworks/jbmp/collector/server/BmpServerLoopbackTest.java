package it.lpworks.jbmp.collector.server;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import it.lpworks.jbmp.collector.config.CollectorProperties;
import it.lpworks.jbmp.collector.enrich.BmpEnricher;
import it.lpworks.jbmp.collector.metrics.CollectorMetrics;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AsPathSegmentType;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginType;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.bmp.PeerFlags;
import it.lpworks.jbmp.protocol.bmp.PeerType;
import it.lpworks.jbmp.protocol.bmp.PerPeerHeader;
import it.lpworks.jbmp.protocol.bmp.stat.AdjRibInRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.StatCounter;
import it.lpworks.jbmp.protocol.builder.BgpUpdateBuilder;
import it.lpworks.jbmp.protocol.builder.BmpMessageBuilder;

/**
 * Loopback test for {@link BmpServer}: a real server on an ephemeral port, a recording fake
 * publisher and a real enricher. A client writes several BMP messages — including one
 * deliberately malformed message between two good ones — and the test asserts via a
 * {@link java.util.concurrent.CountDownLatch} that every good message was published and that
 * the connection survived the malformed one. No Kafka and no Spring context are involved.
 */
class BmpServerLoopbackTest {

    private BmpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void survivesMalformedMessageBetweenGoodOnes() throws Exception {
        // Three good messages will each produce exactly one typed publish:
        //   - a route monitoring (one IPv4 announce -> 1 RouteMonitorMessage),
        //   - a statistics report,
        //   - a route monitoring (one IPv4 announce -> 1 RouteMonitorMessage).
        RecordingBmpMessagePublisher publisher = new RecordingBmpMessagePublisher(3);

        CollectorProperties properties = new CollectorProperties(
                0, 1024, Duration.ofSeconds(30), 0, true, null);
        CollectorMetrics metrics = new CollectorMetrics(new SimpleMeterRegistry());
        server = new BmpServer(properties, new BmpEnricher(), publisher, metrics);
        server.start();

        assertThat(server.boundPort()).isPositive();

        PerPeerHeader peer = peerHeader();
        byte[] goodRouteMonitor1 = routeMonitor(peer, "198.51.100.0", 24);
        byte[] goodStats = BmpMessageBuilder.statisticsReport(
                peer, List.of((StatCounter) new AdjRibInRoutes(42)));
        byte[] goodRouteMonitor2 = routeMonitor(peer, "203.0.113.0", 24);
        byte[] malformed = malformedStatsFrame();

        try (Socket client = new Socket(InetAddress.getLoopbackAddress(), server.boundPort())) {
            OutputStream out = client.getOutputStream();
            out.write(goodRouteMonitor1);
            out.write(malformed);
            out.write(goodStats);
            out.write(goodRouteMonitor2);
            out.flush();

            boolean published = publisher.latch().await(5, TimeUnit.SECONDS);
            assertThat(published)
                    .as("all three good messages published despite the malformed one")
                    .isTrue();
        }

        assertThat(publisher.routeMonitors()).hasSize(2);
        assertThat(publisher.stats()).hasSize(1);
        // Every framed message (including the malformed one) was published raw.
        assertThat(publisher.rawRouterIds()).hasSize(4);
    }

    // ------------------------------------------------------------------
    // Message builders
    // ------------------------------------------------------------------

    private static byte[] routeMonitor(PerPeerHeader peer, String prefix, int bits)
            throws Exception {
        List<PathAttribute> attrs = List.of(
                new Origin(OriginType.IGP),
                new AsPath(List.of(new AsPathSegment(
                        AsPathSegmentType.AS_SEQUENCE, new long[]{65001, 64500}))),
                new NextHop((Inet4Address) InetAddress.getByName("192.0.2.254")));
        byte[] update = BgpUpdateBuilder.update(
                List.of(),
                attrs,
                List.of(new IpPrefix(InetAddress.getByName(prefix), bits)),
                false);
        return BmpMessageBuilder.routeMonitoring(peer, update);
    }

    /**
     * A well-framed BMP message (version 3, correct length, Statistics Report type) whose body
     * is too short to hold the 42-byte per-peer header, so the parser throws but the stream
     * stays byte-aligned for the next message.
     */
    private static byte[] malformedStatsFrame() {
        int bodyLen = 10;
        int total = 6 + bodyLen;
        byte[] frame = new byte[total];
        frame[0] = 3;                       // version
        frame[1] = (byte) (total >>> 24);
        frame[2] = (byte) (total >>> 16);
        frame[3] = (byte) (total >>> 8);
        frame[4] = (byte) total;            // length
        frame[5] = 1;                       // type 1 = Statistics Report
        // The 10 body bytes are left zero; far short of the per-peer header.
        return frame;
    }

    private static PerPeerHeader peerHeader() throws Exception {
        PeerFlags flags = new PeerFlags(false, false, false);
        return new PerPeerHeader(
                PeerType.GLOBAL_INSTANCE,
                flags,
                new byte[8],
                InetAddress.getByName("192.0.2.1"),
                65001,
                (Inet4Address) InetAddress.getByName("192.0.2.10"),
                Instant.ofEpochSecond(1_700_000_000L));
    }
}
