package it.lpworks.jbmp.protocol.bmp.tlv;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * A Termination TLV as carried by Termination messages.
 *
 * <p>See RFC 7854 §4.5. The raw on-wire type code is preserved in {@code rawType}
 * even when {@code type} is {@link TerminationType#UNKNOWN}.
 *
 * @param type    the resolved termination type
 * @param rawType the on-wire type code (unsigned 16-bit), preserved verbatim
 * @param value   the TLV value (defensively copied)
 */
public record TerminationTlv(TerminationType type, int rawType, byte[] value) {

    /**
     * Validates the fields and defensively copies the value.
     */
    public TerminationTlv {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(value, "value");
        value = value.clone();
    }

    /**
     * Returns a defensive copy of the TLV value bytes.
     *
     * @return a fresh copy of the value
     */
    @Override
    public byte[] value() {
        return value.clone();
    }

    /**
     * Decodes the value as a UTF-8 string.
     *
     * @return the value interpreted as UTF-8 text
     */
    public String asString() {
        return new String(value, StandardCharsets.UTF_8);
    }

    /**
     * For a {@link TerminationType#REASON} TLV, decodes the 2-byte big-endian reason
     * code from the start of the value.
     *
     * @return the reason code when at least two value bytes are present, otherwise
     *         an empty {@link OptionalInt}
     */
    public OptionalInt asReasonCode() {
        if (value.length < 2) {
            return OptionalInt.empty();
        }
        return OptionalInt.of(((value[0] & 0xFF) << 8) | (value[1] & 0xFF));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TerminationTlv other)) {
            return false;
        }
        return rawType == other.rawType
                && type == other.type
                && Arrays.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(type, rawType) + Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "TerminationTlv[type=" + type + ", rawType=" + rawType
                + ", value=" + Arrays.toString(value) + ']';
    }
}
