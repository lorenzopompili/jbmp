package it.lpworks.jbmp.mock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Streams generated BMP message bytes to a collector over a single TCP session.
 *
 * <p>For each simulated router the sender opens a {@link Socket} to the configured
 * collector, wraps the socket's output in a {@link BufferedOutputStream}, writes each
 * message produced by the {@link ScenarioGenerator} and flushes. Low-frequency messages
 * (the Initiation message, End-of-RIB markers, Statistics Reports, throttled incremental
 * updates) are flushed individually so they are not stranded in the buffer; the bulk
 * table dump is flushed once it has all been written.
 *
 * <p>When {@code incrementalUpdatesPerSecond} is positive the inter-message delay during
 * the post-dump phase is paced to that rate; the dump itself is sent as fast as the
 * socket accepts it. Each router session runs on its own virtual thread.
 */
public final class TrafficSender {

    private static final Logger LOG = LoggerFactory.getLogger(TrafficSender.class);

    /** Socket connect timeout, in milliseconds. */
    private static final int CONNECT_TIMEOUT_MS = 10_000;

    /** Output buffer size, in bytes, sized to hold a handful of route-monitor messages. */
    private static final int BUFFER_SIZE = 64 * 1024;

    private final MockProperties properties;
    private final ScenarioGenerator generator;

    /**
     * Creates a sender bound to the given configuration and generator.
     *
     * @param properties the mock configuration (target host/port, router count, loop)
     * @param generator  the scenario generator that produces the byte stream
     * @throws NullPointerException if any argument is {@code null}
     */
    public TrafficSender(MockProperties properties, ScenarioGenerator generator) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.generator = Objects.requireNonNull(generator, "generator");
    }

    /**
     * Runs every configured router session, each on its own virtual thread, and blocks
     * until all sessions have finished (or failed).
     *
     * @throws InterruptedException if the calling thread is interrupted while waiting
     */
    public void run() throws InterruptedException {
        int routers = properties.routers();
        Thread[] threads = new Thread[routers];
        for (int routerIndex = 0; routerIndex < routers; routerIndex++) {
            int index = routerIndex;
            threads[routerIndex] = Thread.ofVirtual()
                    .name("jbmp-mock-router-" + routerIndex)
                    .start(() -> runRouter(index));
        }
        for (Thread thread : threads) {
            thread.join();
        }
    }

    /**
     * Runs a single router session, honouring the {@code loop} option by replaying the
     * scenario until the thread is interrupted.
     *
     * @param routerIndex the router index to play
     */
    private void runRouter(int routerIndex) {
        try {
            do {
                sendOnce(routerIndex);
            } while (properties.loop() && !Thread.currentThread().isInterrupted());
        } catch (IOException e) {
            LOG.warn("Router {} session to {}:{} failed: {}",
                    routerIndex, properties.targetHost(), properties.targetPort(), e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Opens one TCP session and streams the full scenario for a router exactly once.
     *
     * @param routerIndex the router index to play
     * @throws IOException          if the connection or any write fails
     * @throws InterruptedException if interrupted while pacing incremental updates
     */
    private void sendOnce(int routerIndex) throws IOException, InterruptedException {
        try (Socket socket = new Socket()) {
            bindSourceAddress(socket, routerIndex);
            socket.connect(
                    new InetSocketAddress(properties.targetHost(), properties.targetPort()),
                    CONNECT_TIMEOUT_MS);
            socket.setTcpNoDelay(true);
            try (OutputStream out = new BufferedOutputStream(socket.getOutputStream(), BUFFER_SIZE)) {
                streamTo(out, routerIndex);
                out.flush();
            }
        }
    }

    /**
     * Binds the socket to a distinct loopback source address per simulated router — used only
     * when more than one router is configured. The collector derives router identity from the
     * connection's source IP, so distinct sources make it treat each as a separate router and
     * spread their traffic across Kafka partitions: the single-host equivalent of real routers
     * with distinct addresses. The whole {@code 127.0.0.0/8} block is loopback.
     *
     * @param socket      the not-yet-connected client socket
     * @param routerIndex the router index, selecting source address {@code 127.0.0.(2+index)}
     * @throws IOException if the bind fails
     */
    private void bindSourceAddress(Socket socket, int routerIndex) throws IOException {
        if (properties.routers() <= 1) {
            return;
        }
        int octet = 2 + (routerIndex % 250);
        socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0." + octet), 0));
    }

    /**
     * Writes the scenario byte stream to the given output. The bulk initial dump streams
     * through the caller's buffered output (flushed when the buffer fills and once at the end
     * of the dump); post-dump incremental messages are flushed individually and paced to the
     * configured update rate.
     *
     * <p>This method is package-private so a loopback test can drive it against an
     * in-process {@link OutputStream} without standing up a socket.
     *
     * @param out         the destination stream (already buffered by the caller)
     * @param routerIndex the router index to play
     * @throws IOException          if a write fails
     * @throws InterruptedException if interrupted while pacing incremental updates
     */
    void streamTo(OutputStream out, int routerIndex) throws IOException, InterruptedException {
        long delayNanos = pacingDelayNanos();
        boolean dumpComplete = false;
        long dumpMessages = expectedDumpMessages();
        long emitted = 0;

        Iterator<byte[]> it = generator.generate(routerIndex).iterator();
        while (it.hasNext()) {
            byte[] message = it.next();
            out.write(message);
            emitted++;

            if (!dumpComplete && emitted >= dumpMessages) {
                // Flush the completed initial dump once, in bulk.
                dumpComplete = true;
                out.flush();
            } else if (dumpComplete) {
                // Post-dump (incremental) phase: flush each low-frequency message so it is
                // delivered promptly, then pace to the configured update rate.
                out.flush();
                if (delayNanos > 0 && it.hasNext()) {
                    sleepNanos(delayNanos);
                }
            }
            // During the bulk dump, writes accumulate in the caller's BufferedOutputStream and
            // flush automatically when it fills, so the dump streams at line rate rather than
            // paying one socket write per message.
        }
    }

    /**
     * Computes the number of messages that make up the preamble and table dump: one
     * Initiation message, a Peer Up per peer, the per-peer dump plus its End-of-RIB
     * marker, and a Statistics Report per peer. Beyond this count the sender begins
     * pacing incremental traffic.
     *
     * @return the dump-phase message count
     */
    private long expectedDumpMessages() {
        long peers = properties.peersPerRouter();
        long perPeerDump = (long) properties.prefixesPerPeer() + 1; // +1 End-of-RIB.
        return 1L + peers + peers * perPeerDump + peers;
    }

    /**
     * Computes the inter-message delay for the incremental phase from the configured
     * updates-per-second rate.
     *
     * @return the delay in nanoseconds, or {@code 0} when pacing is disabled
     */
    private long pacingDelayNanos() {
        int rate = properties.incrementalUpdatesPerSecond();
        return rate > 0 ? TimeUnit.SECONDS.toNanos(1) / rate : 0L;
    }

    /**
     * Sleeps for the given number of nanoseconds, propagating interruption.
     *
     * @param nanos the sleep duration in nanoseconds
     * @throws InterruptedException if interrupted while sleeping
     */
    private static void sleepNanos(long nanos) throws InterruptedException {
        TimeUnit.NANOSECONDS.sleep(nanos);
    }
}
