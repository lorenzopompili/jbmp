package it.lpworks.jbmp.consumer.batch;

/**
 * A callback that commits the Kafka offsets covered by a successfully written batch.
 *
 * <p>The {@link BatchAccumulator} invokes this only after the {@link
 * it.lpworks.jbmp.consumer.store.StoreWriter} has durably written the batch, which realises
 * the offset-after-write guarantee: if the write throws, the committer is never called and
 * Kafka re-delivers the records.
 *
 * <p>In production the token is a Spring Kafka {@code Acknowledgment} whose {@code
 * acknowledge()} the implementation calls; in tests it can be any sentinel the test wants to
 * observe.
 *
 * @param <T> the offset-token type associated with a buffered message
 */
@FunctionalInterface
public interface OffsetCommitter<T> {

    /**
     * Commits the offsets up to and including the supplied token.
     *
     * @param token the offset token of the most recently buffered message in the flushed
     *              batch (never {@code null})
     */
    void commit(T token);
}
