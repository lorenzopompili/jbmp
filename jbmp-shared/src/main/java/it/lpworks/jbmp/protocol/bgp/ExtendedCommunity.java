package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A BGP extended community: an 8-octet opaque value with a high type byte and a
 * sub-type byte.
 *
 * <p>See RFC 4360. The first octet is the high-order type, the second octet the
 * sub-type, and the remaining six octets the type-specific value. This model keeps
 * the raw octets and exposes the common discriminators without imposing a full
 * type-specific decode.
 *
 * @param value the 8-octet community (defensively copied)
 */
public record ExtendedCommunity(byte[] value) {

    /** Required length of an extended community. */
    private static final int LENGTH = 8;

    /** Route Target sub-type code. */
    private static final int SUBTYPE_ROUTE_TARGET = 0x02;

    /**
     * Validates the length and defensively copies the octets.
     */
    public ExtendedCommunity {
        Objects.requireNonNull(value, "value");
        if (value.length != LENGTH) {
            throw new IllegalArgumentException(
                    "ExtendedCommunity must be exactly " + LENGTH
                            + " bytes but was " + value.length);
        }
        value = value.clone();
    }

    /**
     * Returns a defensive copy of the 8 octets.
     *
     * @return a fresh copy of the community octets
     */
    @Override
    public byte[] value() {
        return value.clone();
    }

    /**
     * Returns the high-order type octet.
     *
     * @return {@code value[0]} as an unsigned byte in {@code [0, 255]}
     */
    public int typeHigh() {
        return value[0] & 0xFF;
    }

    /**
     * Returns the sub-type octet.
     *
     * @return {@code value[1]} as an unsigned byte in {@code [0, 255]}
     */
    public int subType() {
        return value[1] & 0xFF;
    }

    /**
     * Reports whether the sub-type identifies a Route Target.
     *
     * @return {@code true} if the sub-type equals {@code 0x02}
     */
    public boolean isRouteTarget() {
        return subType() == SUBTYPE_ROUTE_TARGET;
    }

    /**
     * Returns a hexadecimal rendering of the 8 octets.
     *
     * @return the octets formatted as a lowercase hex string
     */
    public String asText() {
        return HexFormat.of().formatHex(value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ExtendedCommunity other)) {
            return false;
        }
        return Arrays.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "ExtendedCommunity[" + asText() + ']';
    }
}
