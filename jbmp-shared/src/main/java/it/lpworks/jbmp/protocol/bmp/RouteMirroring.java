package it.lpworks.jbmp.protocol.bmp;

import java.util.Arrays;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * A BMP Route Mirroring message.
 *
 * <p>See RFC 7854 §4.7. Carries a verbatim copy of a BGP message (or an information
 * code describing a mirroring event) for a monitored peer. The mirrored BGP message
 * is retained as raw bytes; decoding it is out of scope for this model.
 *
 * @param peerHeader        the per-peer header
 * @param mirroredBgpMessage the raw mirrored BGP message bytes (defensively copied);
 *                           empty when only an information code is present
 * @param informationCode   the mirroring information code, if a code TLV was present
 *                           (unsigned 16-bit), otherwise empty
 */
public record RouteMirroring(
        PerPeerHeader peerHeader,
        byte[] mirroredBgpMessage,
        OptionalInt informationCode) implements BmpMessage {

    /**
     * Validates the fields and defensively copies the mirrored message bytes.
     */
    public RouteMirroring {
        Objects.requireNonNull(peerHeader, "peerHeader");
        Objects.requireNonNull(mirroredBgpMessage, "mirroredBgpMessage");
        Objects.requireNonNull(informationCode, "informationCode");
        mirroredBgpMessage = mirroredBgpMessage.clone();
    }

    /**
     * Returns a defensive copy of the raw mirrored BGP message bytes.
     *
     * @return a fresh copy of the mirrored message
     */
    @Override
    public byte[] mirroredBgpMessage() {
        return mirroredBgpMessage.clone();
    }

    @Override
    public BmpMessageType type() {
        return BmpMessageType.ROUTE_MIRRORING;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RouteMirroring other)) {
            return false;
        }
        return peerHeader.equals(other.peerHeader)
                && Arrays.equals(mirroredBgpMessage, other.mirroredBgpMessage)
                && informationCode.equals(other.informationCode);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(peerHeader, informationCode)
                + Arrays.hashCode(mirroredBgpMessage);
    }

    @Override
    public String toString() {
        return "RouteMirroring[peerHeader=" + peerHeader
                + ", mirroredBgpMessage=" + Arrays.toString(mirroredBgpMessage)
                + ", informationCode=" + informationCode + ']';
    }
}
