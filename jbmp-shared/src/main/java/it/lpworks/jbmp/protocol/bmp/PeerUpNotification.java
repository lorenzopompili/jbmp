package it.lpworks.jbmp.protocol.bmp;

import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A BMP Peer Up Notification.
 *
 * <p>See RFC 7854 §4.10. Sent when a monitored peering session is established. The
 * sent and received BGP OPEN messages are retained as raw bytes; decoding the OPEN
 * message is out of scope for this model.
 *
 * @param peerHeader          the per-peer header
 * @param localAddress        the local address of the TCP session
 * @param localPort           the local TCP port; an unsigned 16-bit value in {@code [0, 65535]}
 * @param remotePort          the remote TCP port; an unsigned 16-bit value in {@code [0, 65535]}
 * @param sentOpenMessage     the raw sent BGP OPEN message bytes (defensively copied)
 * @param receivedOpenMessage the raw received BGP OPEN message bytes (defensively copied)
 * @param informationTlvs     the Information TLVs (immutable copy)
 */
public record PeerUpNotification(
        PerPeerHeader peerHeader,
        InetAddress localAddress,
        int localPort,
        int remotePort,
        byte[] sentOpenMessage,
        byte[] receivedOpenMessage,
        List<InformationTlv> informationTlvs) implements BmpMessage {

    /** Largest representable unsigned 16-bit value. */
    private static final int MAX_UINT16 = 0xFFFF;

    /**
     * Validates the fields and defensively copies the OPEN message bytes and TLV list.
     */
    public PeerUpNotification {
        Objects.requireNonNull(peerHeader, "peerHeader");
        Objects.requireNonNull(localAddress, "localAddress");
        Objects.requireNonNull(sentOpenMessage, "sentOpenMessage");
        Objects.requireNonNull(receivedOpenMessage, "receivedOpenMessage");
        Objects.requireNonNull(informationTlvs, "informationTlvs");
        checkPort("localPort", localPort);
        checkPort("remotePort", remotePort);
        sentOpenMessage = sentOpenMessage.clone();
        receivedOpenMessage = receivedOpenMessage.clone();
        informationTlvs = List.copyOf(informationTlvs);
    }

    private static void checkPort(String name, int port) {
        if (port < 0 || port > MAX_UINT16) {
            throw new IllegalArgumentException(
                    name + " must be a uint16 in [0, " + MAX_UINT16 + "] but was " + port);
        }
    }

    /**
     * Returns a defensive copy of the raw sent OPEN message bytes.
     *
     * @return a fresh copy of the sent OPEN message
     */
    @Override
    public byte[] sentOpenMessage() {
        return sentOpenMessage.clone();
    }

    /**
     * Returns a defensive copy of the raw received OPEN message bytes.
     *
     * @return a fresh copy of the received OPEN message
     */
    @Override
    public byte[] receivedOpenMessage() {
        return receivedOpenMessage.clone();
    }

    @Override
    public BmpMessageType type() {
        return BmpMessageType.PEER_UP;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PeerUpNotification other)) {
            return false;
        }
        return localPort == other.localPort
                && remotePort == other.remotePort
                && peerHeader.equals(other.peerHeader)
                && localAddress.equals(other.localAddress)
                && Arrays.equals(sentOpenMessage, other.sentOpenMessage)
                && Arrays.equals(receivedOpenMessage, other.receivedOpenMessage)
                && informationTlvs.equals(other.informationTlvs);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(peerHeader, localAddress, localPort, remotePort, informationTlvs);
        result = 31 * result + Arrays.hashCode(sentOpenMessage);
        result = 31 * result + Arrays.hashCode(receivedOpenMessage);
        return result;
    }

    @Override
    public String toString() {
        return "PeerUpNotification[peerHeader=" + peerHeader
                + ", localAddress=" + localAddress
                + ", localPort=" + localPort
                + ", remotePort=" + remotePort
                + ", sentOpenMessage=" + Arrays.toString(sentOpenMessage)
                + ", receivedOpenMessage=" + Arrays.toString(receivedOpenMessage)
                + ", informationTlvs=" + informationTlvs + ']';
    }
}
