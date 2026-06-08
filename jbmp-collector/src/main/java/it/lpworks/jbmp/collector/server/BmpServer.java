package it.lpworks.jbmp.collector.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import it.lpworks.jbmp.collector.config.CollectorProperties;
import it.lpworks.jbmp.collector.enrich.BmpEnricher;
import it.lpworks.jbmp.collector.metrics.CollectorMetrics;
import it.lpworks.jbmp.collector.publish.BmpMessagePublisher;

/**
 * The collector's BMP/TCP listener (RFC 7854 §3.2).
 *
 * <p>On {@link ApplicationReadyEvent} — only when {@link CollectorProperties#enabled()} — the
 * server binds a {@link ServerSocket} to the configured port and runs a single-threaded
 * accept loop. Each accepted connection is handed to a {@link RouterSession} that runs on its
 * own virtual thread (one router, one thread, blocking reads), so the listener scales to many
 * concurrent routers without a large platform-thread pool.
 *
 * <p>The number of concurrently active sessions is capped at
 * {@link CollectorProperties#maxRouters()}: connections accepted beyond the cap are closed
 * immediately and counted via {@link CollectorMetrics#connectionRejected()}.
 *
 * <p>The server may also be driven directly (without a Spring context) by constructing it and
 * calling {@link #start()} / {@link #stop()}; this is how the loopback test exercises it. On
 * {@link ContextClosedEvent} (or {@link #stop()}) the accept loop is signalled to stop, the
 * server socket is closed to unblock {@code accept()}, and the session executor is shut down
 * gracefully.
 */
@Component
public class BmpServer {

    private static final Logger log = LoggerFactory.getLogger(BmpServer.class);

    /** How long {@link #stop()} waits for in-flight sessions to drain before forcing shutdown. */
    private static final Duration SHUTDOWN_GRACE = Duration.ofSeconds(5);

    private final CollectorProperties properties;
    private final BmpEnricher enricher;
    private final BmpMessagePublisher publisher;
    private final CollectorMetrics metrics;

    private final AtomicInteger activeRouters = new AtomicInteger();

    private volatile boolean running;
    private volatile ServerSocket serverSocket;
    private volatile ExecutorService sessionExecutor;
    private volatile Thread acceptThread;

    /**
     * Creates the server.
     *
     * @param properties the bound collector properties (never {@code null})
     * @param enricher   the shared, stateless enricher (never {@code null})
     * @param publisher  the message publisher (never {@code null})
     * @param metrics    the metric set (never {@code null})
     */
    public BmpServer(CollectorProperties properties, BmpEnricher enricher,
                     BmpMessagePublisher publisher, CollectorMetrics metrics) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.enricher = Objects.requireNonNull(enricher, "enricher");
        this.publisher = Objects.requireNonNull(publisher, "publisher");
        this.metrics = Objects.requireNonNull(metrics, "metrics");
    }

    /**
     * Starts the listener when the application is ready, unless the collector is disabled.
     *
     * @param event the application-ready event (unused)
     */
    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady(ApplicationReadyEvent event) {
        if (!properties.enabled()) {
            log.info("BMP collector disabled (jbmp.collector.enabled=false); listener not started");
            return;
        }
        start();
    }

    /**
     * Binds the server socket and launches the accept loop on a dedicated thread.
     *
     * <p>Idempotent: a second call while already running is a no-op. The bound port (which may
     * differ from the configured port when {@code 0} requests an ephemeral port) is available
     * via {@link #boundPort()} once this method returns.
     *
     * @throws IllegalStateException if the socket cannot be bound
     */
    public synchronized void start() {
        if (running) {
            return;
        }
        try {
            ServerSocket socket = new ServerSocket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(properties.bmpPort()));
            this.serverSocket = socket;
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to bind BMP listener on port " + properties.bmpPort(), e);
        }
        this.sessionExecutor = Executors.newVirtualThreadPerTaskExecutor();
        this.running = true;
        this.acceptThread = new Thread(this::acceptLoop, "bmp-accept");
        this.acceptThread.setDaemon(true);
        this.acceptThread.start();
        log.info("BMP collector listening on port {} (maxRouters={})",
                boundPort(), properties.maxRouters());
    }

    /**
     * The accept loop: blocks on {@code accept()} and dispatches each socket to a session,
     * enforcing the {@code maxRouters} cap.
     */
    private void acceptLoop() {
        while (running) {
            Socket socket;
            try {
                socket = serverSocket.accept();
            } catch (IOException e) {
                if (running) {
                    log.warn("Accept failed: {}", e.toString());
                }
                // A close() during shutdown surfaces here; the loop exits via the flag.
                break;
            }
            dispatch(socket);
        }
    }

    /**
     * Admits a newly accepted socket, rejecting it if the router cap is already reached.
     *
     * @param socket the accepted client socket
     */
    private void dispatch(Socket socket) {
        int active = activeRouters.incrementAndGet();
        if (active > properties.maxRouters()) {
            activeRouters.decrementAndGet();
            metrics.connectionRejected();
            log.warn("Rejecting connection from {}: maxRouters ({}) reached",
                    socket.getRemoteSocketAddress(), properties.maxRouters());
            closeQuietly(socket);
            return;
        }
        metrics.connectionOpened();
        RouterSession session = new RouterSession(
                socket, properties, enricher, publisher, metrics);
        try {
            sessionExecutor.execute(() -> {
                try {
                    session.run();
                } finally {
                    activeRouters.decrementAndGet();
                    metrics.connectionClosed();
                }
            });
        } catch (RuntimeException e) {
            // Executor rejected (e.g. shutting down): undo the accounting and close.
            activeRouters.decrementAndGet();
            metrics.connectionClosed();
            closeQuietly(socket);
        }
    }

    /**
     * Stops the listener: signals the accept loop, closes the server socket to unblock it, and
     * shuts the session executor down, waiting up to the grace period for sessions to drain.
     *
     * <p>Idempotent and safe to call from {@link #onContextClosed(ContextClosedEvent)} or
     * directly.
     */
    public synchronized void stop() {
        if (!running) {
            return;
        }
        running = false;
        closeQuietly(serverSocket);
        if (acceptThread != null) {
            acceptThread.interrupt();
        }
        ExecutorService executor = this.sessionExecutor;
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(SHUTDOWN_GRACE.toMillis(), TimeUnit.MILLISECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        log.info("BMP collector stopped");
    }

    /**
     * Stops the listener when the application context closes.
     *
     * @param event the context-closed event (unused)
     */
    @EventListener(ContextClosedEvent.class)
    public void onContextClosed(ContextClosedEvent event) {
        stop();
    }

    /**
     * Returns the actual bound port, which equals the configured port unless {@code 0} was
     * configured to request an ephemeral port.
     *
     * @return the bound TCP port, or {@code -1} if the server is not bound
     */
    public int boundPort() {
        ServerSocket socket = this.serverSocket;
        return (socket != null && socket.isBound()) ? socket.getLocalPort() : -1;
    }

    /**
     * Returns the number of currently active router sessions.
     *
     * @return the active session count
     */
    public int activeRouters() {
        return activeRouters.get();
    }

    /**
     * Closes a socket, swallowing any {@link IOException}.
     *
     * @param socket the socket to close (may be {@code null})
     */
    private static void closeQuietly(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Best-effort close.
            }
        }
    }

    /**
     * Closes a server socket, swallowing any {@link IOException}.
     *
     * @param socket the server socket to close (may be {@code null})
     */
    private static void closeQuietly(ServerSocket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Best-effort close.
            }
        }
    }
}
