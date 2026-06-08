package it.lpworks.jbmp.wire;

import java.util.Arrays;
import java.util.Objects;

/**
 * An enriched peering-session lifecycle event derived from a BMP Peer Up Notification
 * (RFC 7854, Section 4.10) or Peer Down Notification (RFC 7854, Section 4.9).
 *
 * <p>The two BMP notifications are unified here: the {@link #eventType()} discriminates
 * between them, and fields not applicable to a given direction simply carry their absent
 * representation (empty array, empty string, or zero).
 *
 * <p>This record is immutable. Every {@code byte[]} is defensively copied on construction
 * and on every accessor; an absent binary field is an empty array, never {@code null}, and
 * an absent text field is an empty string.
 *
 * @param header           the provenance header (never {@code null})
 * @param eventType        whether the session came up or went down (never {@code null})
 * @param remoteIp         the remote (peer) IP address bytes (4 or 16); empty if absent
 * @param remoteAsn        the remote AS number (RFC 6793), as an unsigned 32-bit {@code long}
 * @param remoteBgpId      the remote BGP Identifier (RFC 4271 §4.2); empty if absent
 * @param localIp          the local IP address bytes (4 or 16); empty if absent
 * @param localAsn         the local AS number, as an unsigned 32-bit {@code long}
 * @param localBgpId       the local BGP Identifier; empty if absent
 * @param remotePort       the remote TCP port (Peer Up, RFC 7854 §4.10)
 * @param localPort        the local TCP port (Peer Up, RFC 7854 §4.10)
 * @param peerRd           the peer/VRF Route Distinguisher (RFC 4364); empty string if absent
 * @param prePolicy        the BMP Per-Peer Header L-flag (RFC 7854 §4.2)
 * @param ipv4             {@code true} for an IPv4 peer address family, {@code false} for IPv6
 * @param locRib           the BMP Loc-RIB indication (RFC 9069)
 * @param bmpReason        the Peer Down reason code (RFC 7854 §4.9), or {@code 0} for Peer Up
 * @param bgpErrorCode     the BGP NOTIFICATION Error code (RFC 4271 §4.5), if applicable
 * @param bgpErrorSubcode  the BGP NOTIFICATION Error subcode (RFC 4271 §4.5), if applicable
 * @param errorText        a human-readable description of the down cause; empty if absent
 * @param sentOpen         the raw BGP OPEN (RFC 4271 §4.2) sent to the peer; empty if absent
 * @param receivedOpen     the raw BGP OPEN received from the peer; empty if absent
 * @param infoData         additional information TLV text (RFC 7854); empty if absent
 */
public record PeerEventMessage(
        MessageHeader header,
        PeerEventType eventType,
        byte[] remoteIp,
        long remoteAsn,
        byte[] remoteBgpId,
        byte[] localIp,
        long localAsn,
        byte[] localBgpId,
        int remotePort,
        int localPort,
        String peerRd,
        boolean prePolicy,
        boolean ipv4,
        boolean locRib,
        int bmpReason,
        int bgpErrorCode,
        int bgpErrorSubcode,
        String errorText,
        byte[] sentOpen,
        byte[] receivedOpen,
        String infoData) {

    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * Canonicalises every field: empty arrays/strings replace {@code null} and all arrays
     * are defensively copied.
     *
     * @throws NullPointerException if {@code header} or {@code eventType} is {@code null}
     */
    public PeerEventMessage {
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(eventType, "eventType");

        remoteIp = copyOrEmpty(remoteIp);
        remoteBgpId = copyOrEmpty(remoteBgpId);
        localIp = copyOrEmpty(localIp);
        localBgpId = copyOrEmpty(localBgpId);
        sentOpen = copyOrEmpty(sentOpen);
        receivedOpen = copyOrEmpty(receivedOpen);

        peerRd = (peerRd == null) ? "" : peerRd;
        errorText = (errorText == null) ? "" : errorText;
        infoData = (infoData == null) ? "" : infoData;
    }

    private static byte[] copyOrEmpty(byte[] b) {
        return (b == null || b.length == 0) ? EMPTY_BYTES : b.clone();
    }

    /** @return a defensive copy of the remote IP bytes */
    @Override
    public byte[] remoteIp() {
        return remoteIp.clone();
    }

    /** @return a defensive copy of the remote BGP identifier bytes */
    @Override
    public byte[] remoteBgpId() {
        return remoteBgpId.clone();
    }

    /** @return a defensive copy of the local IP bytes */
    @Override
    public byte[] localIp() {
        return localIp.clone();
    }

    /** @return a defensive copy of the local BGP identifier bytes */
    @Override
    public byte[] localBgpId() {
        return localBgpId.clone();
    }

    /** @return a defensive copy of the sent OPEN bytes */
    @Override
    public byte[] sentOpen() {
        return sentOpen.clone();
    }

    /** @return a defensive copy of the received OPEN bytes */
    @Override
    public byte[] receivedOpen() {
        return receivedOpen.clone();
    }

    /**
     * Value equality with element-wise comparison of every byte array.
     *
     * @param o the object to compare with
     * @return {@code true} if {@code o} is an equal {@code PeerEventMessage}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PeerEventMessage other)) {
            return false;
        }
        return remoteAsn == other.remoteAsn
                && localAsn == other.localAsn
                && remotePort == other.remotePort
                && localPort == other.localPort
                && prePolicy == other.prePolicy
                && ipv4 == other.ipv4
                && locRib == other.locRib
                && bmpReason == other.bmpReason
                && bgpErrorCode == other.bgpErrorCode
                && bgpErrorSubcode == other.bgpErrorSubcode
                && header.equals(other.header)
                && eventType == other.eventType
                && Arrays.equals(remoteIp, other.remoteIp)
                && Arrays.equals(remoteBgpId, other.remoteBgpId)
                && Arrays.equals(localIp, other.localIp)
                && Arrays.equals(localBgpId, other.localBgpId)
                && peerRd.equals(other.peerRd)
                && errorText.equals(other.errorText)
                && Arrays.equals(sentOpen, other.sentOpen)
                && Arrays.equals(receivedOpen, other.receivedOpen)
                && infoData.equals(other.infoData);
    }

    /**
     * Hash code consistent with {@link #equals(Object)} (array-aware).
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        int result = header.hashCode();
        result = 31 * result + eventType.hashCode();
        result = 31 * result + Arrays.hashCode(remoteIp);
        result = 31 * result + Long.hashCode(remoteAsn);
        result = 31 * result + Arrays.hashCode(remoteBgpId);
        result = 31 * result + Arrays.hashCode(localIp);
        result = 31 * result + Long.hashCode(localAsn);
        result = 31 * result + Arrays.hashCode(localBgpId);
        result = 31 * result + remotePort;
        result = 31 * result + localPort;
        result = 31 * result + peerRd.hashCode();
        result = 31 * result + Boolean.hashCode(prePolicy);
        result = 31 * result + Boolean.hashCode(ipv4);
        result = 31 * result + Boolean.hashCode(locRib);
        result = 31 * result + bmpReason;
        result = 31 * result + bgpErrorCode;
        result = 31 * result + bgpErrorSubcode;
        result = 31 * result + errorText.hashCode();
        result = 31 * result + Arrays.hashCode(sentOpen);
        result = 31 * result + Arrays.hashCode(receivedOpen);
        result = 31 * result + infoData.hashCode();
        return result;
    }

    /**
     * Renders a diagnostic representation with array contents expanded.
     *
     * @return a human-readable representation
     */
    @Override
    public String toString() {
        return "PeerEventMessage["
                + "header=" + header
                + ", eventType=" + eventType
                + ", remoteIp=" + Arrays.toString(remoteIp)
                + ", remoteAsn=" + remoteAsn
                + ", remoteBgpId=" + Arrays.toString(remoteBgpId)
                + ", localIp=" + Arrays.toString(localIp)
                + ", localAsn=" + localAsn
                + ", localBgpId=" + Arrays.toString(localBgpId)
                + ", remotePort=" + remotePort
                + ", localPort=" + localPort
                + ", peerRd=" + peerRd
                + ", prePolicy=" + prePolicy
                + ", ipv4=" + ipv4
                + ", locRib=" + locRib
                + ", bmpReason=" + bmpReason
                + ", bgpErrorCode=" + bgpErrorCode
                + ", bgpErrorSubcode=" + bgpErrorSubcode
                + ", errorText=" + errorText
                + ", sentOpen=" + Arrays.toString(sentOpen)
                + ", receivedOpen=" + Arrays.toString(receivedOpen)
                + ", infoData=" + infoData
                + ']';
    }
}
