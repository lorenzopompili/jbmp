package it.lpworks.jbmp.consumer.batch;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import it.lpworks.jbmp.consumer.store.StoreWriter;
import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * The route-monitoring batching engine.
 *
 * <p>It buffers decoded {@link RouteMonitorMessage}s together with an opaque
 * <em>offset token</em> per message and flushes the buffer to a {@link StoreWriter} when
 * either trigger fires:
 * <ul>
 *   <li><b>size</b> — the buffer reaches the configured {@code batchSize}; the flush happens
 *       synchronously inside {@link #add(RouteMonitorMessage, Object)};</li>
 *   <li><b>time</b> — {@code flushInterval} has elapsed since the current (non-empty) batch
 *       was opened, as observed by {@link #tick()} (or by a subsequent {@code add}).</li>
 * </ul>
 *
 * <h2>Offset-after-write guarantee</h2>
 * <p>A flush first calls {@link StoreWriter#writeRouteMonitorBatch(List)} and then
 * {@link StoreWriter#applyRibState(List)}; only if <em>both</em> return normally is the
 * {@link OffsetCommitter} invoked with the token of the most recently buffered message. If
 * either store call throws, the buffer and its tokens are <em>retained</em>, the committer is
 * not called, and the exception propagates to the caller so that Kafka offsets are withheld
 * and the records are re-delivered. The retained buffer means a subsequent successful flush
 * (e.g. after a transient store failure clears) still writes the records exactly once into
 * the historical store from the consumer's point of view.
 *
 * <h2>Threading and time</h2>
 * <p>The mutating operations ({@code add}, {@code tick}, {@code flush}) are {@code
 * synchronized} on the instance, so a Kafka listener thread feeding records and the scheduled
 * tick thread driving time-based flushes cannot interleave and corrupt the buffer. The lock is
 * uncontended on the common add path. Time is supplied by an injected {@link Clock} so tests
 * advance it deterministically with no real sleeping.
 *
 * @param <T> the offset-token type associated with each buffered message
 */
public final class BatchAccumulator<T> {

    private final StoreWriter store;
    private final int batchSize;
    private final Duration flushInterval;
    private final Clock clock;
    private final OffsetCommitter<T> committer;

    private final List<RouteMonitorMessage> buffer;
    private T lastToken;
    private Instant batchOpenedAt;

    /**
     * Creates a batching engine.
     *
     * @param store         the sink that durably writes flushed batches (never {@code null})
     * @param batchSize     the size trigger; must be positive
     * @param flushInterval the age trigger for an open batch; must be a positive duration
     * @param clock         the time source consulted on {@code add}/{@code tick} (never
     *                      {@code null})
     * @param committer     the offset-commit callback invoked after a successful flush (never
     *                      {@code null})
     * @throws NullPointerException     if {@code store}, {@code flushInterval}, {@code clock}
     *                                  or {@code committer} is {@code null}
     * @throws IllegalArgumentException if {@code batchSize} is not positive or
     *                                  {@code flushInterval} is not a positive duration
     */
    public BatchAccumulator(StoreWriter store, int batchSize, Duration flushInterval,
            Clock clock, OffsetCommitter<T> committer) {
        this.store = Objects.requireNonNull(store, "store");
        this.flushInterval = Objects.requireNonNull(flushInterval, "flushInterval");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.committer = Objects.requireNonNull(committer, "committer");
        if (batchSize <= 0) {
            throw new IllegalArgumentException("batchSize must be positive but was " + batchSize);
        }
        if (flushInterval.isZero() || flushInterval.isNegative()) {
            throw new IllegalArgumentException(
                    "flushInterval must be a positive duration but was " + flushInterval);
        }
        this.batchSize = batchSize;
        this.buffer = new ArrayList<>(Math.min(batchSize, 1024));
    }

    /**
     * Buffers one route-monitoring message and its offset token, flushing first if the
     * pending batch has already aged past {@code flushInterval}, and again afterwards if the
     * buffer has reached {@code batchSize}.
     *
     * <p>If a flush is triggered and the store throws, the exception propagates and the
     * message that was being added is still buffered (its token recorded), so no offsets are
     * lost.
     *
     * @param message the decoded route-monitoring message (never {@code null})
     * @param token   the offset token to commit once this message has been durably written
     *                (never {@code null})
     * @throws NullPointerException if {@code message} or {@code token} is {@code null}
     */
    public synchronized void add(RouteMonitorMessage message, T token) {
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(token, "token");

        // A late-arriving record may find the open batch already overdue: flush it first so
        // the time trigger is honoured even on a busy partition that never calls tick().
        if (!buffer.isEmpty() && isOverdue()) {
            flush();
        }

        if (buffer.isEmpty()) {
            batchOpenedAt = clock.instant();
        }
        buffer.add(message);
        lastToken = token;

        if (buffer.size() >= batchSize) {
            flush();
        }
    }

    /**
     * Advances the engine's notion of time and flushes the pending batch if it has aged past
     * {@code flushInterval}. This is the time-trigger entry point the Kafka wiring calls on
     * an idle poll (and tests call to drive time-based flushes).
     *
     * @return {@code true} if a non-empty batch was flushed, {@code false} otherwise
     * @throws RuntimeException if the store throws during the flush (offsets are withheld)
     */
    public synchronized boolean tick() {
        if (!buffer.isEmpty() && isOverdue()) {
            flush();
            return true;
        }
        return false;
    }

    /**
     * Forces a flush of the pending batch regardless of its size or age. A no-op when the
     * buffer is empty.
     *
     * <p>On success the buffer is cleared and the {@link OffsetCommitter} is invoked with the
     * last buffered token. On failure the buffer is left intact and the exception propagates.
     *
     * @throws RuntimeException if the store throws (the buffer and tokens are retained and no
     *                          offsets are committed)
     */
    public synchronized void flush() {
        if (buffer.isEmpty()) {
            return;
        }
        // An unmodifiable view of the live buffer: the store reads it, and we only clear the
        // backing list after both store calls succeed, so a thrown exception preserves state.
        List<RouteMonitorMessage> batch = List.copyOf(buffer);
        store.writeRouteMonitorBatch(batch);
        store.applyRibState(batch);

        // Both writes succeeded: it is now safe to drop the buffer and commit the offsets.
        T token = lastToken;
        buffer.clear();
        lastToken = null;
        batchOpenedAt = null;
        committer.commit(token);
    }

    /**
     * Returns the number of route-monitoring messages currently buffered (not yet flushed).
     *
     * @return the pending message count
     */
    public synchronized int pending() {
        return buffer.size();
    }

    private boolean isOverdue() {
        return !Duration.between(batchOpenedAt, clock.instant()).minus(flushInterval).isNegative();
    }
}
