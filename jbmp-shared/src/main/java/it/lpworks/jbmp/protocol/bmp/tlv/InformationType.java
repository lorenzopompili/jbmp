package it.lpworks.jbmp.protocol.bmp.tlv;

/**
 * The type code of an Information TLV carried by Initiation and Peer Up messages.
 *
 * <p>Types 0-2 are defined in RFC 7854 §4.4; the VRF/Table Name (3) and Admin Label
 * (4) information types are defined in RFC 9069. {@link #UNKNOWN} preserves any
 * unrecognised type code.
 */
public enum InformationType {

    /** Free-form UTF-8 string (type 0). */
    STRING(0),
    /** sysDescr, the system description (type 1). */
    SYS_DESCR(1),
    /** sysName, the system name (type 2). */
    SYS_NAME(2),
    /** VRF/Table Name (type 3, RFC 9069). */
    VRF_TABLE_NAME(3),
    /** Admin Label (type 4, RFC 9069). */
    ADMIN_LABEL(4),
    /** Synthetic value representing any unrecognised type code. */
    UNKNOWN(-1);

    private final int code;

    InformationType(int code) {
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
     * Resolves an information type from its on-wire code, mapping any unrecognised
     * code to {@link #UNKNOWN}.
     *
     * @param code the unsigned 16-bit type code
     * @return the matching type, never {@code null}
     */
    public static InformationType fromCode(int code) {
        for (InformationType type : values()) {
            if (type != UNKNOWN && type.code == code) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
