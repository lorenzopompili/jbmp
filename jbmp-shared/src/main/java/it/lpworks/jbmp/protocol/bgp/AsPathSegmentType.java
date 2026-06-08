package it.lpworks.jbmp.protocol.bgp;

import java.util.Optional;

/**
 * The type of an AS_PATH segment.
 *
 * <p>AS_SET and AS_SEQUENCE are defined in RFC 4271 §4.3; the confederation segment
 * types are defined in RFC 5065.
 */
public enum AsPathSegmentType {

    /** An unordered set of ASNs (type 1). */
    AS_SET(1),
    /** An ordered sequence of ASNs (type 2). */
    AS_SEQUENCE(2),
    /** An ordered sequence of confederation member ASNs (type 3, RFC 5065). */
    AS_CONFED_SEQUENCE(3),
    /** An unordered set of confederation member ASNs (type 4, RFC 5065). */
    AS_CONFED_SET(4);

    private final int code;

    AsPathSegmentType(int code) {
        this.code = code;
    }

    /**
     * Returns the on-wire segment-type code.
     *
     * @return the unsigned 8-bit code in {@code [1, 4]}
     */
    public int code() {
        return code;
    }

    /**
     * Resolves a segment type from its on-wire code.
     *
     * @param code the unsigned 8-bit code
     * @return the matching type, or empty if unrecognised
     */
    public static Optional<AsPathSegmentType> fromCode(int code) {
        for (AsPathSegmentType type : values()) {
            if (type.code == code) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }
}
