package it.lpworks.jbmp.protocol;

import java.util.OptionalInt;

/**
 * Unchecked exception raised when a BMP (RFC 7854) or BGP (RFC 4271) message
 * cannot be decoded from its wire representation.
 *
 * <p>When the failure can be attributed to a specific byte position the absolute
 * offset (relative to the start of the underlying buffer) is retained and exposed
 * through {@link #offset()} to aid diagnostics.
 */
public final class BmpParseException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Absolute byte offset of the failure, or a negative sentinel when unknown. */
    private final int offsetBytes;

    /** Whether {@link #offsetBytes} carries a meaningful value. */
    private final boolean hasOffset;

    /**
     * Creates an exception with a human-readable message and no associated offset.
     *
     * @param message description of the failure
     */
    public BmpParseException(String message) {
        super(message);
        this.offsetBytes = -1;
        this.hasOffset = false;
    }

    /**
     * Creates an exception with a human-readable message and the absolute byte
     * offset at which decoding failed.
     *
     * @param message     description of the failure
     * @param offsetBytes absolute byte offset (relative to the backing buffer)
     */
    public BmpParseException(String message, int offsetBytes) {
        super(message);
        this.offsetBytes = offsetBytes;
        this.hasOffset = true;
    }

    /**
     * Creates an exception wrapping an underlying cause and no associated offset.
     *
     * @param message description of the failure
     * @param cause   the underlying cause
     */
    public BmpParseException(String message, Throwable cause) {
        super(message, cause);
        this.offsetBytes = -1;
        this.hasOffset = false;
    }

    /**
     * Returns the absolute byte offset of the failure when known.
     *
     * @return the offset, or an empty {@link OptionalInt} when no offset was recorded
     */
    public OptionalInt offset() {
        return hasOffset ? OptionalInt.of(offsetBytes) : OptionalInt.empty();
    }
}
