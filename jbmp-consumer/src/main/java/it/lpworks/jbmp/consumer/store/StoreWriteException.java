package it.lpworks.jbmp.consumer.store;

/**
 * An unchecked failure raised by a {@link StoreWriter} when a batch or single-message write
 * could not be fully persisted.
 *
 * <p>It exists so the all-or-nothing {@link StoreWriter} contract surfaces as a propagating
 * runtime exception: the batching engine lets it bubble up, the Kafka offset is withheld, and
 * the records are re-delivered.
 */
public class StoreWriteException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception with a message and cause.
     *
     * @param message the detail message
     * @param cause   the underlying failure (typically a {@link java.sql.SQLException})
     */
    public StoreWriteException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates an exception with a message.
     *
     * @param message the detail message
     */
    public StoreWriteException(String message) {
        super(message);
    }
}
