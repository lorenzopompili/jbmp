package it.lpworks.jbmp.collector.server;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import it.lpworks.jbmp.collector.config.CollectorProperties;
import it.lpworks.jbmp.collector.enrich.BmpEnricher;
import it.lpworks.jbmp.collector.metrics.CollectorMetrics;
import it.lpworks.jbmp.identity.UuidFactory;
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
import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationType;
import it.lpworks.jbmp.protocol.builder.BgpUpdateBuilder;
import it.lpworks.jbmp.protocol.builder.BmpMessageBuilder;
import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * Loopback tests that the collector derives a router's identity solely from its TCP source IP
 * address — matching the reference collector — and that a BMP Initiation {@code sysName}
 * (RFC 7854 §4.3, {@link InformationType#SYS_NAME}) does <strong>not</strong> change it. A real
 * {@link BmpServer} on an ephemeral port runs a real {@link RouterSession}/{@link BmpEnricher},
 * and a client writes an Initiation followed by a Route Monitoring; the published
 * {@link RouteMonitorMessage}'s router id is asserted.
 *
 * <p>This pins down the faithful, fair identity rule: the router id is the hash of the source IP
 * regardless of {@code sysName}, so a router resolves to the same identity (and Kafka partition)
 * as in the reference system.
 */
class RouterSessionSysNameTest {

    private BmpServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void initiationSysNameDoesNotChangeRouterId() throws Exception {
        RecordingBmpMessagePublisher publisher = startServer(1);

        PerPeerHeader peer = peerHeader();
        byte[] initiation = initiationWithSysName("router-A");
        byte[] routeMonitor = routeMonitor(peer, "198.51.100.0", 24);

        sendAndAwait(publisher, initiation, routeMonitor);

        assertThat(publisher.routeMonitors()).hasSize(1);
        RouteMonitorMessage msg = publisher.routeMonitors().get(0);

        // The router id is the IP-based identity; the sysName is ignored for identity.
        assertThat(msg.header().routerId())
                .isEqualTo(UuidFactory.router(loopbackBytes()))
                .isNotEqualTo(UuidFactory.router("router-A".getBytes(UTF_8)));
    }

    @Test
    void distinctSysNamesOnOneSourceIpYieldTheSameRouterId() throws Exception {
        // Two routers behind one source IP advertising different system names still resolve to
        // the one IP-based identity, matching the reference collector (no sysName-based split).
        UUID idA = routerIdForSysName("router-A");
        UUID idB = routerIdForSysName("router-B");

        assertThat(idA).isEqualTo(UuidFactory.router(loopbackBytes()));
        assertThat(idB).isEqualTo(idA);
    }

    @Test
    void noInitiationFallsBackToIpRouterId() throws Exception {
        RecordingBmpMessagePublisher publisher = startServer(1);

        PerPeerHeader peer = peerHeader();
        byte[] routeMonitor = routeMonitor(peer, "198.51.100.0", 24);

        // No Initiation: the router never identifies itself, so the IP-based default stands.
        sendAndAwait(publisher, routeMonitor);

        assertThat(publisher.routeMonitors()).hasSize(1);
        assertThat(publisher.routeMonitors().get(0).header().routerId())
                .isEqualTo(UuidFactory.router(loopbackBytes()));
    }

    // ------------------------------------------------------------------
    // Harness
    // ------------------------------------------------------------------

    /**
     * Runs one Initiation+RouteMonitoring exchange for the given system name and returns the
     * router id stamped on the published route-monitor message.
     */
    private UUID routerIdForSysName(String sysName) throws Exception {
        RecordingBmpMessagePublisher publisher = startServer(1);
        sendAndAwait(publisher,
                initiationWithSysName(sysName),
                routeMonitor(peerHeader(), "203.0.113.0", 24));
        UUID id = publisher.routeMonitors().get(0).header().routerId();
        server.stop();
        server = null;
        return id;
    }

    private RecordingBmpMessagePublisher startServer(int expectedTypedPublishes) {
        RecordingBmpMessagePublisher publisher =
                new RecordingBmpMessagePublisher(expectedTypedPublishes);
        CollectorProperties properties = new CollectorProperties(
                0, 1024, Duration.ofSeconds(30), 0, true, null);
        CollectorMetrics metrics = new CollectorMetrics(new SimpleMeterRegistry());
        server = new BmpServer(properties, new BmpEnricher(), publisher, metrics);
        server.start();
        assertThat(server.boundPort()).isPositive();
        return publisher;
    }

    /**
     * Connects to the server, writes the given frames, and blocks (keeping the socket open) on
     * the publisher latch so the session reads the whole stream before the connection closes.
     *
     * @param publisher the recording publisher whose latch gates completion
     * @param frames    the fully framed BMP messages to send, in order
     */
    private void sendAndAwait(RecordingBmpMessagePublisher publisher, byte[]... frames)
            throws Exception {
        try (Socket client = new Socket(InetAddress.getLoopbackAddress(), server.boundPort())) {
            OutputStream out = client.getOutputStream();
            for (byte[] frame : frames) {
                out.write(frame);
            }
            out.flush();
            assertThat(publisher.latch().await(5, TimeUnit.SECONDS))
                    .as("expected publishes landed before the socket closed")
                    .isTrue();
        }
    }

    // ------------------------------------------------------------------
    // Message builders
    // ------------------------------------------------------------------

    private static byte[] initiationWithSysName(String sysName) {
        InformationTlv tlv = new InformationTlv(
                InformationType.SYS_NAME,
                InformationType.SYS_NAME.code(),
                sysName.getBytes(UTF_8));
        return BmpMessageBuilder.initiation(List.of(tlv));
    }

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

    private static byte[] loopbackBytes() {
        return InetAddress.getLoopbackAddress().getAddress();
    }
}
