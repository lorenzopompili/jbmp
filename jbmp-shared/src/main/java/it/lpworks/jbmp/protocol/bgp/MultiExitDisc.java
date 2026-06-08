package it.lpworks.jbmp.protocol.bgp;

/**
 * The MULTI_EXIT_DISC (MED) path attribute (type code 4).
 *
 * <p>See RFC 4271 §5.1.4.
 *
 * @param med the MED value; an unsigned 32-bit value in {@code [0, 4294967295]}
 */
public record MultiExitDisc(long med) implements PathAttribute {

    /** Largest representable unsigned 32-bit value. */
    private static final long MAX_UINT32 = 0xFFFFFFFFL;

    /**
     * Validates that the MED is an unsigned 32-bit value.
     */
    public MultiExitDisc {
        if (med < 0 || med > MAX_UINT32) {
            throw new IllegalArgumentException(
                    "med must be a uint32 in [0, " + MAX_UINT32 + "] but was " + med);
        }
    }

    @Override
    public int typeCode() {
        return 4;
    }
}
