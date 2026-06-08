package it.lpworks.jbmp.protocol.bgp;

/**
 * The LOCAL_PREF path attribute (type code 5).
 *
 * <p>See RFC 4271 §5.1.5.
 *
 * @param localPreference the local preference; an unsigned 32-bit value in
 *                        {@code [0, 4294967295]}
 */
public record LocalPref(long localPreference) implements PathAttribute {

    /** Largest representable unsigned 32-bit value. */
    private static final long MAX_UINT32 = 0xFFFFFFFFL;

    /**
     * Validates that the local preference is an unsigned 32-bit value.
     */
    public LocalPref {
        if (localPreference < 0 || localPreference > MAX_UINT32) {
            throw new IllegalArgumentException(
                    "localPreference must be a uint32 in [0, " + MAX_UINT32
                            + "] but was " + localPreference);
        }
    }

    @Override
    public int typeCode() {
        return 5;
    }
}
