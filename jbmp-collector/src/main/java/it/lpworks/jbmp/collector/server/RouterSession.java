package it.lpworks.jbmp.collector.server;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.lpworks.jbmp.collector.config.CollectorProperties;
import it.lpworks.jbmp.collector.enrich.BmpEnricher;
import it.lpworks.jbmp.collector.enrich.EnrichmentContext;
import it.lpworks.jbmp.collector.metrics.CollectorMetrics;
import it.lpworks.jbmp.collector.publish.BmpMessagePublisher;
import it.lpworks.jbmp.identity.UuidFactory;
import it.lpworks.jbmp.protocol.bmp.BmpMessage;
import it.lpworks.jbmp.protocol.bmp.InitiationMessage;
import it.lpworks.jbmp.protocol.bmp.PeerDownNotification;
import it.lpworks.jbmp.protocol.bmp.PeerUpNotification;
import it.lpworks.jbmp.protocol.bmp.RouteMirroring;
import it.lpworks.jbmp.protocol.bmp.RouteMonitoring;
import it.lpworks.jbmp.protocol.bmp.StatisticsReport;
import it.lpworks.jbmp.protocol.bmp.TerminationMessage;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationType;
import it.lpworks.jbmp.protocol.parser.ParseMode;
import it.lpworks.jbmp.protocol.parser.bmp.BmpParser;
import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * Handles one router's BMP/TCP session on a single (virtual) thread.
 *
 * <p>The session reads the BMP byte stream message-by-message: the 6-byte common header
 * (RFC 7854 §4.1) gives the protocol version and the total message length, then the remaining
 * {@code length - 6} bytes complete the message. Each fully framed message is parsed in
 * {@link ParseMode#LENIENT}, published verbatim to the raw topic, then enriched and published
 * as typed DTOs.
 *
 * <h2>Router identity</h2>
 * <p>The session derives the router's identity from its TCP source IP address: the
 * {@linkplain EnrichmentContext#routerKey() router key} is the source IP, hashed by
 * {@link UuidFactory#router(byte[])}. This matches the reference collector's IP-based router
 * identity, so a given router resolves to the same identity (and the same Kafka partition) in
 * both systems. A BMP Initiation {@code sysName} (RFC 7854 §4.3) is logged but does not change
 * the identity.
 *
 * <h2>Robustness</h2>
 * <p>A failure to parse or enrich one message is caught, counted via
 * {@link CollectorMetrics#parseError()} and skipped — the connection is <strong>not</strong>
 * torn down, because BMP is a long-lived stream and a single malformed message must not cost a
 * router its session. The loop ends only on end-of-stream, a read timeout, a socket close, or
 * a framing error that desynchronises the stream (an unreadable length leaves no safe way to
 * resynchronise).
 */
public final class RouterSession {

    private static final Logger log = LoggerFactory.getLogger(RouterSession.class);

    /** Length, in octets, of the BMP common header (RFC 7854 §4.1). */
    private static final int COMMON_HEADER_LEN = 6;

    /** The mandatory BMP protocol version (RFC 7854 §4.1). */
    private static final int BMP_VERSION = 3;

    /** Hard upper bound on a single BMP message, guarding against a corrupt length field. */
    private static final long MAX_MESSAGE_LEN = 16 * 1024 * 1024;

    private final Socket socket;
    private final CollectorProperties properties;
    private final BmpEnricher enricher;
    private final BmpMessagePublisher publisher;
    private final CollectorMetrics metrics;
    private final byte[] routerIp;
    private final EnrichmentContext context;

    /** Reusable header scratch buffer; one per session, never shared across threads. */
    private final byte[] headerBuffer = new byte[COMMON_HEADER_LEN];

    /**
     * Creates a session bound to one accepted socket.
     *
     * @param socket     the accepted client socket (never {@code null})
     * @param properties the bound collector properties (never {@code null})
     * @param enricher   the shared enricher (never {@code null})
     * @param publisher  the message publisher (never {@code null})
     * @param metrics    the metric set (never {@code null})
     */
    public RouterSession(Socket socket, CollectorProperties properties, BmpEnricher enricher,
                         BmpMessagePublisher publisher, CollectorMetrics metrics) {
        this.socket = socket;
        this.properties = properties;
        this.enricher = enricher;
        this.publisher = publisher;
        this.metrics = metrics;
        this.routerIp = socket.getInetAddress().getAddress();
        // The router key is the TCP source IP, fixed for the whole connection (see EnrichmentContext).
        this.context = new EnrichmentContext(
                routerIp, properties.collectorId(), RouterSession::nowNanos);
    }

    /**
     * Runs the read loop until the stream ends, times out, or is closed.
     *
     * <p>The socket read timeout is set to {@link CollectorProperties#readTimeout()}; a
     * timeout ends the session cleanly. All I/O resources are released on exit.
     */
    public void run() {
        try {
            socket.setSoTimeout((int) Math.min(properties.readTimeout().toMillis(),
                    Integer.MAX_VALUE));
            InputStream in = socket.getInputStream();
            readLoop(in);
        } catch (SocketTimeoutException e) {
            log.debug("Router {} read timed out; closing session", socket.getRemoteSocketAddress());
        } catch (EOFException e) {
            log.debug("Router {} closed the connection", socket.getRemoteSocketAddress());
        } catch (IOException e) {
            log.debug("Router {} session ended: {}",
                    socket.getRemoteSocketAddress(), e.toString());
        } finally {
            closeQuietly();
        }
    }

    /**
     * The core framing/parse/publish loop.
     *
     * @param in the socket input stream
     * @throws IOException on end-of-stream, timeout, or socket error
     */
    private void readLoop(InputStream in) throws IOException {
        while (true) {
            // 1) Read exactly the 6-byte common header.
            if (!readFully(in, headerBuffer, COMMON_HEADER_LEN)) {
                return; // Clean end-of-stream between messages.
            }

            int version = headerBuffer[0] & 0xFF;
            if (version != BMP_VERSION) {
                // The stream is desynchronised; there is no safe resync point.
                log.warn("Router {} sent unsupported BMP version {}; closing session",
                        socket.getRemoteSocketAddress(), version);
                metrics.parseError();
                return;
            }

            long messageLength = readUint32(headerBuffer, 1);
            if (messageLength < COMMON_HEADER_LEN || messageLength > MAX_MESSAGE_LEN) {
                log.warn("Router {} declared illegal BMP message length {}; closing session",
                        socket.getRemoteSocketAddress(), messageLength);
                metrics.parseError();
                return;
            }

            // 2) Read the rest of the message and assemble the full PDU.
            int bodyLength = (int) (messageLength - COMMON_HEADER_LEN);
            byte[] full = new byte[(int) messageLength];
            System.arraycopy(headerBuffer, 0, full, 0, COMMON_HEADER_LEN);
            if (!readFully(in, full, COMMON_HEADER_LEN, bodyLength)) {
                // The peer closed mid-message; nothing more will arrive.
                throw new EOFException("Truncated BMP message body");
            }

            // 3) Publish the raw bytes, then parse/enrich/publish — never killing the loop.
            handleMessage(full);
        }
    }

    /**
     * Processes one fully framed BMP message: raw publish, parse, enrich, typed publish.
     *
     * <p>Any exception from parsing or enrichment is absorbed: it increments the parse-error
     * metric and returns so the next message can be read.
     *
     * @param full the complete BMP message bytes, common header included
     */
    private void handleMessage(byte[] full) {
        // Derive the router id from the router key (the TCP source IP), matching the reference
        // collector's IP-based router identity.
        UUID routerId = UuidFactory.router(context.routerKey());
        try {
            publisher.publishRaw(routerId, full);
        } catch (RuntimeException e) {
            // The publisher contract forbids throwing, but guard the loop regardless.
            log.debug("Raw publish failed for router {}: {}",
                    socket.getRemoteSocketAddress(), e.toString());
        }

        BmpMessage message;
        try {
            message = BmpParser.parse(full, ParseMode.LENIENT);
        } catch (RuntimeException e) {
            metrics.parseError();
            log.debug("Failed to parse BMP message from router {}: {}",
                    socket.getRemoteSocketAddress(), e.toString());
            return;
        }

        try {
            metrics.messageParsed(message.type().name());
            dispatch(message);
        } catch (RuntimeException e) {
            metrics.parseError();
            log.debug("Failed to enrich/publish BMP message from router {}: {}",
                    socket.getRemoteSocketAddress(), e.toString());
        }
    }

    /**
     * Enriches a parsed message and publishes the resulting DTO(s). Initiation and Termination
     * carry no enriched DTO and are only logged.
     *
     * @param message the parsed BMP message
     */
    private void dispatch(BmpMessage message) {
        switch (message) {
            case RouteMonitoring rm -> {
                List<RouteMonitorMessage> routes = enricher.enrichRouteMonitoring(rm, context);
                for (RouteMonitorMessage route : routes) {
                    publisher.publishRouteMonitor(route);
                }
            }
            case PeerUpNotification up ->
                    publisher.publishPeerEvent(enricher.enrichPeerUp(up, context));
            case PeerDownNotification down ->
                    publisher.publishPeerEvent(enricher.enrichPeerDown(down, context));
            case StatisticsReport stats ->
                    publisher.publishStats(enricher.enrichStatisticsReport(stats, context));
            case RouteMirroring mirror ->
                    publisher.publishRouteMirror(enricher.enrichRouteMirroring(mirror, context));
            case InitiationMessage initiation -> handleInitiation(initiation);
            case TerminationMessage ignored ->
                    log.debug("Termination from router {}", socket.getRemoteSocketAddress());
        }
    }

    /**
     * Handles a BMP Initiation message (RFC 7854 §4.3). Per the RFC this is the first message of a
     * monitoring session and carries Information TLVs (§4.4) such as {@code sysName}; jBMP uses it
     * purely for diagnostics. When debug logging is enabled this logs the session start, surfacing
     * the {@code sysName} TLV ({@link InformationType#SYS_NAME}) when one is present.
     *
     * <p>The Initiation message does <strong>not</strong> influence router identity: the router id
     * is derived from the TCP source IP (see {@link #handleMessage(byte[])}) and stays stable for
     * the whole connection regardless of any advertised {@code sysName}.
     *
     * @param initiation the parsed Initiation message
     */
    private void handleInitiation(InitiationMessage initiation) {
        if (!log.isDebugEnabled()) {
            return;
        }
        for (InformationTlv tlv : initiation.informationTlvs()) {
            if (tlv.type() == InformationType.SYS_NAME && !isBlank(tlv.value())) {
                log.debug("Initiation from router {} (sysName={})",
                        socket.getRemoteSocketAddress(),
                        new String(tlv.value(), StandardCharsets.UTF_8).strip());
                return;
            }
        }
        log.debug("Initiation from router {} (no sysName)", socket.getRemoteSocketAddress());
    }

    /**
     * Reports whether a {@code sysName} value is blank — empty or all whitespace when decoded
     * as UTF-8.
     *
     * @param value the raw {@code sysName} bytes
     * @return {@code true} if the value carries no non-whitespace character
     */
    private static boolean isBlank(byte[] value) {
        return new String(value, StandardCharsets.UTF_8).isBlank();
    }


    // ------------------------------------------------------------------
    // Stream helpers
    // ------------------------------------------------------------------

    /**
     * Reads exactly {@code length} bytes into the start of {@code buffer}.
     *
     * @return {@code true} if all bytes were read; {@code false} on a clean end-of-stream
     *         before any byte was read
     * @throws IOException if the stream ends part-way or another I/O error occurs
     */
    private static boolean readFully(InputStream in, byte[] buffer, int length)
            throws IOException {
        return readFully(in, buffer, 0, length);
    }

    /**
     * Reads exactly {@code length} bytes into {@code buffer} starting at {@code offset}.
     *
     * @return {@code true} if all bytes were read; {@code false} on a clean end-of-stream
     *         before any byte was read at {@code offset}
     * @throws IOException if the stream ends after some but not all bytes, or on I/O error
     */
    private static boolean readFully(InputStream in, byte[] buffer, int offset, int length)
            throws IOException {
        int read = 0;
        while (read < length) {
            int n = in.read(buffer, offset + read, length - read);
            if (n < 0) {
                if (read == 0) {
                    return false; // Clean boundary: nothing was pending.
                }
                throw new EOFException("Stream ended after " + read + " of " + length + " bytes");
            }
            read += n;
        }
        return true;
    }

    /**
     * Reads a big-endian unsigned 32-bit value from {@code buffer} at {@code offset}.
     *
     * @return the value in {@code [0, 4294967295]}
     */
    private static long readUint32(byte[] buffer, int offset) {
        return ((long) (buffer[offset] & 0xFF) << 24)
                | ((long) (buffer[offset + 1] & 0xFF) << 16)
                | ((long) (buffer[offset + 2] & 0xFF) << 8)
                | (buffer[offset + 3] & 0xFF);
    }

    /**
     * Returns the current time in nanoseconds since the Unix epoch (millisecond resolution).
     *
     * @return the wall-clock receive timestamp in nanoseconds
     */
    private static long nowNanos() {
        return System.currentTimeMillis() * 1_000_000L;
    }

    /**
     * Closes the socket, swallowing any {@link IOException}.
     */
    private void closeQuietly() {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Best-effort close.
        }
    }
}
