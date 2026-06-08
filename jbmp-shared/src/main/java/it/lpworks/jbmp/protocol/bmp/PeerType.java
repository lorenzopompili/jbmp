package it.lpworks.jbmp.protocol.bmp;

import java.util.Optional;

/**
 * The peer type field of the per-peer header.
 *
 * <p>Types 0-2 are defined in RFC 7854 §4.2; the Loc-RIB instance peer (type 3) is
 * defined in RFC 9069.
 */
public enum PeerType {

    /** Global Instance Peer (type 0). */
    GLOBAL_INSTANCE(0),
    /** RD Instance Peer (type 1). */
    RD_INSTANCE(1),
    /** Local Instance Peer (type 2). */
    LOCAL_INSTANCE(2),
    /** Loc-RIB Instance Peer (type 3), per RFC 9069. */
    LOC_RIB(3);

    private final int code;

    PeerType(int code) {
        this.code = code;
    }

    /**
     * Returns the on-wire peer-type code.
     *
     * @return the unsigned 8-bit code
     */
    public int code() {
        return code;
    }

    /**
     * Resolves a peer type from its on-wire code.
     *
     * @param code the unsigned 8-bit code
     * @return the matching type, or empty if unrecognised
     */
    public static Optional<PeerType> fromCode(int code) {
        for (PeerType type : values()) {
            if (type.code == code) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }
}
