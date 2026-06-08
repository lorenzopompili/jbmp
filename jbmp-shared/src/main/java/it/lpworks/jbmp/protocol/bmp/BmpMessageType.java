package it.lpworks.jbmp.protocol.bmp;

import java.util.Optional;

/**
 * The BMP message type carried in the common header.
 *
 * <p>See RFC 7854 §4.1 (and RFC 9069 for the Local RIB extension which reuses
 * the existing route-monitoring type).
 */
public enum BmpMessageType {

    /** Route Monitoring (type 0). */
    ROUTE_MONITORING(0),
    /** Statistics Report (type 1). */
    STATISTICS_REPORT(1),
    /** Peer Down Notification (type 2). */
    PEER_DOWN(2),
    /** Peer Up Notification (type 3). */
    PEER_UP(3),
    /** Initiation (type 4). */
    INITIATION(4),
    /** Termination (type 5). */
    TERMINATION(5),
    /** Route Mirroring (type 6). */
    ROUTE_MIRRORING(6);

    private final int code;

    BmpMessageType(int code) {
        this.code = code;
    }

    /**
     * Returns the on-wire type code.
     *
     * @return the unsigned 8-bit code in {@code [0, 6]}
     */
    public int code() {
        return code;
    }

    /**
     * Resolves a message type from its on-wire code.
     *
     * @param code the unsigned 8-bit type code
     * @return the matching type, or empty if the code is unrecognised
     */
    public static Optional<BmpMessageType> fromCode(int code) {
        for (BmpMessageType type : values()) {
            if (type.code == code) {
                return Optional.of(type);
            }
        }
        return Optional.empty();
    }
}
