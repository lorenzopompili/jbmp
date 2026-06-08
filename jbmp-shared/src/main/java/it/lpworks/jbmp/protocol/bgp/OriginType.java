package it.lpworks.jbmp.protocol.bgp;

import java.util.Optional;

/**
 * The value of the BGP ORIGIN path attribute.
 *
 * <p>See RFC 4271 §4.3 / §5.1.1.
 */
public enum OriginType {

    /** Interior Gateway Protocol (value 0). */
    IGP(0),
    /** Exterior Gateway Protocol (value 1). */
    EGP(1),
    /** Incomplete / learned by some other means (value 2). */
    INCOMPLETE(2);

    private final int code;

    OriginType(int code) {
        this.code = code;
    }

    /**
     * Returns the on-wire ORIGIN code.
     *
     * @return the unsigned 8-bit code in {@code [0, 2]}
     */
    public int code() {
        return code;
    }

    /**
     * Resolves an origin from its on-wire code.
     *
     * @param code the unsigned 8-bit code
     * @return the matching origin, or empty if unrecognised
     */
    public static Optional<OriginType> fromCode(int code) {
        for (OriginType origin : values()) {
            if (origin.code == code) {
                return Optional.of(origin);
            }
        }
        return Optional.empty();
    }
}
