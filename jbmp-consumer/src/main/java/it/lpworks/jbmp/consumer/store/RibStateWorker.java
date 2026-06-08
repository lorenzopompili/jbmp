package it.lpworks.jbmp.consumer.store;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * Applies the {@code rib_state} projection asynchronously, off the consumer's
 * offset-commit path.
 *
 * <p>The current-state projection is an idempotent upsert/delete keyed by
 * {@code (peer, prefix, path id)} and is fully rebuildable from the append-only
 * {@code route_monitor} history. Applying it inline — thousands of {@code INSERT ... ON
 * CONFLICT} statements per poll — would serialise behind every historical batch and cap the
 * consumer at the upsert rate. Instead each flushed batch is handed to this single background
 * worker, so the historical bulk-copy path commits its Kafka offset immediately and the
 * projection catches up behind it.
 *
 * <p>A single worker thread keeps the projection's writes serial (no self-contention between
 * concurrent upserts of the same key). The hand-off queue is bounded; when the projection
 * falls behind the burst the oldest pending batch is dropped (the projection stays eventually
 * consistent and is reconcilable from the history), keeping memory bounded under load. A failed
 * batch is logged and skipped for the same reason.
 *
 * <p>This decouples only the rebuildable projection; the append-only history retains its
 * strict offset-after-write guarantee on the caller's path.
 */
public final class RibStateWorker implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(RibStateWorker.class);
    private static final Duration SHUTDOWN_GRACE = Duration.ofSeconds(20);

    private final StoreWriter store;
    private final BlockingQueue<List<RouteMonitorMessage>> queue;
    private final Thread worker;
    private final AtomicLong droppedBatches = new AtomicLong();
    private volatile boolean running = true;

    /**
     * Starts the worker.
     *
     * @param store      the persistence sink whose {@link StoreWriter#applyRibState(List)} is
     *                   invoked off-thread (never {@code null})
     * @param queueDepth the maximum number of pending batches buffered before the oldest is
     *                   dropped; must be positive
     * @throws NullPointerException     if {@code store} is {@code null}
     * @throws IllegalArgumentException if {@code queueDepth} is not positive
     */
    public RibStateWorker(StoreWriter store, int queueDepth) {
        this.store = Objects.requireNonNull(store, "store");
        if (queueDepth <= 0) {
            throw new IllegalArgumentException("queueDepth must be positive but was " + queueDepth);
        }
        this.queue = new ArrayBlockingQueue<>(queueDepth);
        this.worker = new Thread(this::run, "rib-state-worker");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    /**
     * Hands a flushed route-monitor batch to the background projection. Non-blocking: if the
     * buffer is full the oldest pending batch is discarded so the caller is never throttled.
     *
     * @param batch the batch just written to the historical store (never {@code null})
     */
    public void submit(List<RouteMonitorMessage> batch) {
        Objects.requireNonNull(batch, "batch");
        if (batch.isEmpty()) {
            return;
        }
        if (queue.offer(batch)) {
            return;
        }
        if (queue.poll() != null) {
            droppedBatches.incrementAndGet();
        }
        if (!queue.offer(batch)) {
            droppedBatches.incrementAndGet();
        }
    }

    private void run() {
        while (running || !queue.isEmpty()) {
            List<RouteMonitorMessage> batch;
            try {
                batch = queue.poll(200, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (batch == null) {
                continue;
            }
            try {
                store.applyRibState(batch);
            } catch (RuntimeException e) {
                // The projection is rebuildable from the history; skip the failed batch rather
                // than wedge the worker, and surface it for monitoring.
                log.warn("rib_state batch failed and was skipped (projection stays eventually "
                        + "consistent)", e);
            }
        }
    }

    /**
     * Returns the number of batches dropped because the projection could not keep up with the
     * ingest burst. A persistently non-zero value indicates the projection is lagging.
     *
     * @return the dropped-batch count
     */
    public long droppedBatches() {
        return droppedBatches.get();
    }

    /**
     * Stops the worker, draining the pending queue within a grace period.
     */
    @Override
    public void close() {
        running = false;
        worker.interrupt();
        try {
            worker.join(SHUTDOWN_GRACE.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
