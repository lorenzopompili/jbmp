package it.lpworks.jbmp.protocol.bmp.tlv;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * An Information TLV as carried by Initiation and Peer Up messages.
 *
 * <p>See RFC 7854 §4.4 (and RFC 9069 for the additional information types). The
 * raw on-wire type code is preserved in {@code rawType} even when {@code type} is
 * {@link InformationType#UNKNOWN}.
 *
 * @param type    the resolved information type
 * @param rawType the on-wire type code (unsigned 16-bit), preserved verbatim
 * @param value   the TLV value (defensively copied)
 */
public record InformationTlv(InformationType type, int rawType, byte[] value) {

    /**
     * Validates the fields and defensively copies the value.
     */
    public InformationTlv {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof InformationTlv other)) {
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
        return "InformationTlv[type=" + type + ", rawType=" + rawType
                + ", value=" + Arrays.toString(value) + ']';
    }
}
