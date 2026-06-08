package it.lpworks.jbmp.protocol.bmp;

import it.lpworks.jbmp.protocol.bmp.tlv.TerminationTlv;

import java.util.List;
import java.util.Objects;

/**
 * A BMP Termination message.
 *
 * <p>See RFC 7854 §4.4. Sent to indicate that the monitoring session is being closed,
 * encoded as a list of Termination TLVs.
 *
 * @param tlvs the Termination TLVs (immutable copy)
 */
public record TerminationMessage(List<TerminationTlv> tlvs) implements BmpMessage {

    /**
     * Validates and defensively copies the TLV list.
     */
    public TerminationMessage {
        Objects.requireNonNull(tlvs, "tlvs");
        tlvs = List.copyOf(tlvs);
    }

    @Override
    public BmpMessageType type() {
        return BmpMessageType.TERMINATION;
    }
}
