package it.lpworks.jbmp.protocol.bmp;

/**
 * The reason a monitored peer session went down, as reported in a Peer Down
 * Notification.
 *
 * <p>Reasons 1-4 are defined in RFC 7854 §4.9; reasons 5 (peer deallocated) and 6
 * (local system closed without a NOTIFICATION) are defined in RFC 9069.
 * {@link #UNKNOWN} is a synthetic value used to preserve unrecognised reason codes.
 */
public enum PeerDownReason {

    /** The local system closed the session and sent a BGP NOTIFICATION (reason 1). */
    LOCAL_NOTIFICATION(1),
    /** The local system closed the session for an FSM event (reason 2). */
    LOCAL_FSM(2),
    /** The remote system closed the session and sent a BGP NOTIFICATION (reason 3). */
    REMOTE_NOTIFICATION(3),
    /** The remote system closed the session without a NOTIFICATION (reason 4). */
    REMOTE_NO_NOTIFICATION(4),
    /** The peer was de-configured / de-allocated (reason 5, RFC 9069). */
    PEER_DEALLOCATED(5),
    /** The local system closed the session without a NOTIFICATION (reason 6, RFC 9069). */
    LOCAL_NO_NOTIFICATION(6),
    /** Synthetic value representing any unrecognised reason code. */
    UNKNOWN(-1);

    private final int code;

    PeerDownReason(int code) {
        this.code = code;
    }

    /**
     * Returns the on-wire reason code, or {@code -1} for {@link #UNKNOWN}.
     *
     * @return the reason code
     */
    public int code() {
        return code;
    }

    /**
     * Resolves a reason from its on-wire code, mapping any unrecognised code to
     * {@link #UNKNOWN}.
     *
     * @param code the unsigned 8-bit reason code
     * @return the matching reason, never {@code null}
     */
    public static PeerDownReason fromCode(int code) {
        for (PeerDownReason reason : values()) {
            if (reason != UNKNOWN && reason.code == code) {
                return reason;
            }
        }
        return UNKNOWN;
    }
}
