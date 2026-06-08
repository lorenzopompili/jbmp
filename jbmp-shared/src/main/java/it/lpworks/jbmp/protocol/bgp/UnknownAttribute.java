package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * A catch-all path attribute preserving the raw value for type codes not otherwise
 * modelled.
 *
 * <p>See RFC 4271 §4.3 for the generic attribute framing.
 *
 * @param typeCode the on-wire attribute type code (unsigned 8-bit)
 * @param flags    the decoded attribute flags
 * @param value    the raw attribute value (defensively copied)
 */
public record UnknownAttribute(int typeCode, AttributeFlags flags, byte[] value)
        implements PathAttribute {

    /**
     * Validates and defensively copies the raw value.
     */
    public UnknownAttribute {
        Objects.requireNonNull(flags, "flags");
        Objects.requireNonNull(value, "value");
        value = value.clone();
    }

    /**
     * Returns a defensive copy of the raw value bytes.
     *
     * @return a fresh copy of the value
     */
    @Override
    public byte[] value() {
        return value.clone();
    }

    /**
     * Returns the on-wire attribute type code.
     *
     * @return the type code
     */
    @Override
    public int typeCode() {
        return typeCode;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UnknownAttribute other)) {
            return false;
        }
        return typeCode == other.typeCode
                && flags.equals(other.flags)
                && Arrays.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(typeCode, flags) + Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "UnknownAttribute[typeCode=" + typeCode + ", flags=" + flags
                + ", value=" + Arrays.toString(value) + ']';
    }
}
