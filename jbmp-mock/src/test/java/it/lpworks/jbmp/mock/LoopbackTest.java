package it.lpworks.jbmp.mock;

import static org.assertj.core.api.Assertions.assertThat;

import it.lpworks.jbmp.protocol.bmp.BmpMessage;
import it.lpworks.jbmp.protocol.bmp.BmpMessageType;
import it.lpworks.jbmp.protocol.parser.ParseMode;
import it.lpworks.jbmp.protocol.parser.bmp.BmpParser;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

/**
 * End-to-end loopback test for {@link TrafficSender}: a plain {@link ServerSocket} on an
 * ephemeral port runs on a background virtual thread, frames and parses every BMP message
 * it receives, and the test asserts (via a {@link CountDownLatch}, with no
 * {@link Thread#sleep}) that the parsed stream matches what the generator produced.
 *
 * <p>No Spring context, no Kafka and no external infrastructure is involved — only
 * loopback TCP.
 */
class LoopbackTest {

    /** How long the test will wait for the full message stream to arrive. */
    private static final long TIMEOUT_SECONDS = 30L;

    @Test
    void senderStreamMatchesGeneratorOverLoopback() throws Exception {
        int peers = 2;
        int prefixes = 50;
        MockProperties props = new MockProperties(
                "localhost", 0, 1, peers, prefixes, "initial-dump", 0, false, false);

        ScenarioGenerator generator = new ScenarioGenerator(props);
        List<byte[]> expected = generator.generateAll(0);
        int expectedCount = expected.size();

        CountDownLatch allReceived = new CountDownLatch(expectedCount);
        List<BmpMessage> received = new CopyOnWriteArrayList<>();
        AtomicReference<Throwable> serverError = new AtomicReference<>();

        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress("localhost", 0));
            int port = server.getLocalPort();

            Thread acceptor = Thread.ofVirtual().name("loopback-acceptor").start(() -> {
                try (Socket client = server.accept();
                     InputStream in = client.getInputStream()) {
                    readFramedMessages(in, expectedCount, received, allReceived);
                } catch (IOException e) {
                    serverError.set(e);
                    // Drain the latch so the test fails fast instead of timing out.
                    while (allReceived.getCount() > 0) {
                        allReceived.countDown();
                    }
                }
            });

            MockProperties connectProps = new MockProperties(
                    "localhost", port, 1, peers, prefixes, "initial-dump", 0, false, false);
            TrafficSender sender = new TrafficSender(connectProps, new ScenarioGenerator(connectProps));
            sender.run();

            boolean completed = allReceived.await(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            acceptor.join(TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));

            assertThat(serverError.get()).isNull();
            assertThat(completed)
                    .as("all %d messages received within %ds", expectedCount, TIMEOUT_SECONDS)
                    .isTrue();
        }

        assertThat(received).hasSize(expectedCount);

        // The received stream must decode to the same message types in the same order as
        // the generator's own output.
        List<BmpMessageType> expectedTypes = expected.stream()
                .map(bytes -> BmpParser.parse(bytes, ParseMode.STRICT).type())
                .toList();
        List<BmpMessageType> receivedTypes = received.stream().map(BmpMessage::type).toList();
        assertThat(receivedTypes).containsExactlyElementsOf(expectedTypes);
    }

    /**
     * Reads exactly {@code count} fully-framed BMP messages from the stream, parsing each
     * with {@link BmpParser} and counting down the latch as each one arrives.
     *
     * <p>BMP framing (RFC 7854 §4.1): a 6-octet common header whose bytes 1-4 hold the
     * total message length (header included). The header is read first, the declared
     * remainder is read next, and the reassembled message is parsed.
     *
     * @param in       the socket input stream
     * @param count    the number of messages to read
     * @param sink     the destination for parsed messages
     * @param latch    counted down once per received message
     * @throws IOException if the stream ends early or a read fails
     */
    private static void readFramedMessages(InputStream in, int count, List<BmpMessage> sink,
                                           CountDownLatch latch) throws IOException {
        DataInputStream data = new DataInputStream(in);
        for (int i = 0; i < count; i++) {
            byte[] header = new byte[6];
            data.readFully(header);
            long totalLength = ((long) (header[1] & 0xFF) << 24)
                    | ((header[2] & 0xFF) << 16)
                    | ((header[3] & 0xFF) << 8)
                    | (header[4] & 0xFF);
            if (totalLength < 6) {
                throw new EOFException("Illegal BMP message length: " + totalLength);
            }
            byte[] message = new byte[(int) totalLength];
            System.arraycopy(header, 0, message, 0, 6);
            data.readFully(message, 6, (int) totalLength - 6);

            sink.add(BmpParser.parse(message, ParseMode.STRICT));
            latch.countDown();
        }
    }

    @Test
    void loopOptionReplaysTheScenario() throws Exception {
        int peers = 1;
        int prefixes = 3;
        MockProperties baseProps = new MockProperties(
                "localhost", 0, 1, peers, prefixes, "initial-dump", 0, true, false);
        int perRound = new ScenarioGenerator(baseProps).generateAll(0).size();
        int rounds = 2;
        int expectedCount = perRound * rounds;

        List<BmpMessage> received = new CopyOnWriteArrayList<>();

        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress("localhost", 0));
            // Bound accept() so the test can never hang if the sender misbehaves.
            server.setSoTimeout((int) TimeUnit.SECONDS.toMillis(TIMEOUT_SECONDS));
            int port = server.getLocalPort();

            MockProperties loopProps = new MockProperties(
                    "localhost", port, 1, peers, prefixes, "initial-dump", 0, true, false);
            TrafficSender sender = new TrafficSender(loopProps, new ScenarioGenerator(loopProps));
            Thread senderThread = Thread.ofVirtual().name("looping-sender").start(() -> {
                try {
                    sender.run();
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });

            try {
                // The looping sender opens a fresh connection per round. Accept connections
                // and drain each to EOF (the sender closes after each round) until we have at
                // least `rounds` worth of messages. Draining to EOF — rather than closing
                // after a fixed count — avoids racing the sender's own socket close, and the
                // accept() soTimeout guarantees termination.
                int guard = 0;
                while (received.size() < expectedCount && guard++ < rounds + 4) {
                    try (Socket client = server.accept();
                         InputStream in = client.getInputStream()) {
                        readUntilEof(in, received);
                    } catch (SocketTimeoutException e) {
                        break;
                    }
                }
            } finally {
                // Stop the infinite loop; closing the server (try-with-resources) drops any
                // further connections the sender may already have opened.
                senderThread.interrupt();
            }
        }

        assertThat(received).hasSizeGreaterThanOrEqualTo(expectedCount);
        // Each round begins with an Initiation message.
        assertThat(received.get(0).type()).isEqualTo(BmpMessageType.INITIATION);
        assertThat(received.get(perRound).type()).isEqualTo(BmpMessageType.INITIATION);
    }

    /**
     * Reads fully-framed BMP messages from one connection until the peer closes it (EOF),
     * parsing each and appending it to the sink.
     *
     * @param in   the connection input stream
     * @param sink the destination for parsed messages
     */
    private static void readUntilEof(InputStream in, List<BmpMessage> sink) {
        DataInputStream data = new DataInputStream(in);
        try {
            while (true) {
                byte[] header = new byte[6];
                data.readFully(header);
                long totalLength = ((long) (header[1] & 0xFF) << 24)
                        | ((header[2] & 0xFF) << 16)
                        | ((header[3] & 0xFF) << 8)
                        | (header[4] & 0xFF);
                byte[] message = new byte[(int) totalLength];
                System.arraycopy(header, 0, message, 0, 6);
                data.readFully(message, 6, (int) totalLength - 6);
                sink.add(BmpParser.parse(message, ParseMode.STRICT));
            }
        } catch (IOException eof) {
            // Connection closed for this round.
        }
    }
}
