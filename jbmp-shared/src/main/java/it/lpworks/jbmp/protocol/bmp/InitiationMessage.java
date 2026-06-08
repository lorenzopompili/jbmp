package it.lpworks.jbmp.protocol.bmp;

import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;

import java.util.List;
import java.util.Objects;

/**
 * A BMP Initiation message.
 *
 * <p>See RFC 7854 §4.3. Sent once at the start of a monitoring session to convey
 * information about the sender, encoded as a list of Information TLVs.
 *
 * @param informationTlvs the Information TLVs (immutable copy)
 */
public record InitiationMessage(List<InformationTlv> informationTlvs) implements BmpMessage {

    /**
     * Validates and defensively copies the TLV list.
     */
    public InitiationMessage {
        Objects.requireNonNull(informationTlvs, "informationTlvs");
        informationTlvs = List.copyOf(informationTlvs);
    }

    @Override
    public BmpMessageType type() {
        return BmpMessageType.INITIATION;
    }
}
