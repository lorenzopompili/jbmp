package it.lpworks.jbmp.protocol.bmp.tlv;

/**
 * The type code of a Termination TLV carried by Termination messages.
 *
 * <p>See RFC 7854 §4.5. {@link #UNKNOWN} preserves any unrecognised type code.
 */
public enum TerminationType {

    /** Free-form UTF-8 string (type 0). */
    STRING(0),
    /** Reason code (type 1). */
    REASON(1),
    /** Synthetic value representing any unrecognised type code. */
    UNKNOWN(-1);

    private final int code;

    TerminationType(int code) {
        this.code = code;
    }

    /**
     * Returns the on-wire type code, or {@code -1} for {@link #UNKNOWN}.
     *
     * @return the type code
     */
    public int code() {
        return code;
    }

    /**
     * Resolves a termination type from its on-wire code, mapping any unrecognised
     * code to {@link #UNKNOWN}.
     *
     * @param code the unsigned 16-bit type code
     * @return the matching type, never {@code null}
     */
    public static TerminationType fromCode(int code) {
        for (TerminationType type : values()) {
            if (type != UNKNOWN && type.code == code) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
