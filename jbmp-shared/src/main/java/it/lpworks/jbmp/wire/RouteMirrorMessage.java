package it.lpworks.jbmp.wire;

import java.util.Arrays;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * An enriched route-mirroring event derived from a BMP Route Mirroring message (RFC 7854,
 * Section 4.7).
 *
 * <p>Route Mirroring verbatim-copies a BGP PDU observed on the wire, optionally with an
 * Information TLV (RFC 7854 §4.7) carrying a numeric Information Code (e.g. errored PDU,
 * messages lost). The mirrored BGP message is retained as opaque bytes.
 *
 * <p>This record is immutable; the mirrored-message array is defensively copied on
 * construction and on access, and is an empty array (never {@code null}) when absent.
 *
 * @param header           the provenance header (never {@code null})
 * @param mirroredMessage  the raw mirrored BGP PDU bytes (RFC 7854 §4.7); empty if absent
 * @param informationCode  the Information TLV code (RFC 7854 §4.7), if present
 */
public record RouteMirrorMessage(
        MessageHeader header,
        byte[] mirroredMessage,
        OptionalInt informationCode) {

    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * Canonicalises the fields: copies the mirrored message (empty when {@code null}) and
     * substitutes an empty {@link OptionalInt} for a {@code null} information code.
     *
     * @throws NullPointerException if {@code header} is {@code null}
     */
    public RouteMirrorMessage {
        Objects.requireNonNull(header, "header");
        mirroredMessage = (mirroredMessage == null || mirroredMessage.length == 0)
                ? EMPTY_BYTES : mirroredMessage.clone();
        informationCode = (informationCode == null) ? OptionalInt.empty() : informationCode;
    }

    /** @return a defensive copy of the mirrored BGP PDU bytes */
    @Override
    public byte[] mirroredMessage() {
        return mirroredMessage.clone();
    }

    /**
     * Value equality with element-wise comparison of the mirrored-message array.
     *
     * @param o the object to compare with
     * @return {@code true} if {@code o} is an equal {@code RouteMirrorMessage}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RouteMirrorMessage other)) {
            return false;
        }
        return header.equals(other.header)
                && Arrays.equals(mirroredMessage, other.mirroredMessage)
                && informationCode.equals(other.informationCode);
    }

    /**
     * Hash code consistent with {@link #equals(Object)} (array-aware).
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        int result = header.hashCode();
        result = 31 * result + Arrays.hashCode(mirroredMessage);
        result = 31 * result + informationCode.hashCode();
        return result;
    }

    /**
     * Renders a diagnostic representation with the mirrored-message bytes expanded.
     *
     * @return a human-readable representation
     */
    @Override
    public String toString() {
        return "RouteMirrorMessage["
                + "header=" + header
                + ", mirroredMessage=" + Arrays.toString(mirroredMessage)
                + ", informationCode=" + informationCode
                + ']';
    }
}
