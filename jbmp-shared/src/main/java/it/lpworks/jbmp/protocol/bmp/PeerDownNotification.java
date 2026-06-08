package it.lpworks.jbmp.protocol.bmp;

import java.util.Arrays;
import java.util.Objects;

/**
 * A BMP Peer Down Notification.
 *
 * <p>See RFC 7854 §4.9 (and RFC 9069 for additional reason codes). Sent when a
 * monitored peering session goes down. The raw on-wire reason code is preserved in
 * {@code reasonCode} alongside the resolved {@link PeerDownReason}; {@code data}
 * holds the reason-specific payload (for example, the BGP NOTIFICATION message).
 *
 * @param peerHeader the per-peer header
 * @param reasonCode the on-wire reason code (unsigned 8-bit), preserved verbatim
 * @param reason     the resolved reason
 * @param data       the reason-specific payload bytes (defensively copied)
 */
public record PeerDownNotification(
        PerPeerHeader peerHeader,
        int reasonCode,
        PeerDownReason reason,
        byte[] data) implements BmpMessage {

    /**
     * Validates the fields and defensively copies the payload.
     */
    public PeerDownNotification {
        Objects.requireNonNull(peerHeader, "peerHeader");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(data, "data");
        data = data.clone();
    }

    /**
     * Returns a defensive copy of the reason-specific payload.
     *
     * @return a fresh copy of the payload bytes
     */
    @Override
    public byte[] data() {
        return data.clone();
    }

    @Override
    public BmpMessageType type() {
        return BmpMessageType.PEER_DOWN;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PeerDownNotification other)) {
            return false;
        }
        return reasonCode == other.reasonCode
                && reason == other.reason
                && peerHeader.equals(other.peerHeader)
                && Arrays.equals(data, other.data);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(peerHeader, reasonCode, reason) + Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "PeerDownNotification[peerHeader=" + peerHeader
                + ", reasonCode=" + reasonCode
                + ", reason=" + reason
                + ", data=" + Arrays.toString(data) + ']';
    }
}
