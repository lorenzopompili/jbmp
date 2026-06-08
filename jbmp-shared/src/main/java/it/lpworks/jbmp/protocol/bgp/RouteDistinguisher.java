package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * A Route Distinguisher used to make VPN routes globally unique.
 *
 * <p>See RFC 4364 §4.2. The on-wire form is a 2-octet type followed by a 6-octet
 * value; this model stores the value verbatim and renders it per the type:
 * <ul>
 *   <li>type 0: {@code 2-byte-asn:4-byte-number};</li>
 *   <li>type 1: {@code ipv4-address:2-byte-number};</li>
 *   <li>type 2: {@code 4-byte-asn:2-byte-number}.</li>
 * </ul>
 *
 * @param type  the RD type (typically 0, 1 or 2)
 * @param value the 6-octet value (defensively copied)
 */
public record RouteDistinguisher(int type, byte[] value) {

    /** Required length of the RD value field. */
    private static final int VALUE_LEN = 6;

    /**
     * Validates the length and defensively copies the octets.
     */
    public RouteDistinguisher {
        Objects.requireNonNull(value, "value");
        if (value.length != VALUE_LEN) {
            throw new IllegalArgumentException(
                    "RouteDistinguisher value must be exactly " + VALUE_LEN
                            + " bytes but was " + value.length);
        }
        value = value.clone();
    }

    /**
     * Returns a defensive copy of the 6-octet value.
     *
     * @return a fresh copy of the value octets
     */
    @Override
    public byte[] value() {
        return value.clone();
    }

    /**
     * Renders the RD in its canonical textual form for the known types, falling back
     * to a {@code type:hex} rendering for any other type.
     *
     * @return the textual representation
     */
    public String asText() {
        return switch (type) {
            case 0 -> {
                int asn = read16(0);
                long num = read32(2);
                yield asn + ":" + num;
            }
            case 1 -> {
                String ip = (value[0] & 0xFF) + "." + (value[1] & 0xFF) + "."
                        + (value[2] & 0xFF) + "." + (value[3] & 0xFF);
                int num = read16(4);
                yield ip + ":" + num;
            }
            case 2 -> {
                long asn = read32(0);
                int num = read16(4);
                yield asn + ":" + num;
            }
            default -> type + ":" + HexFormat.of().formatHex(value);
        };
    }

    private int read16(int at) {
        return ((value[at] & 0xFF) << 8) | (value[at + 1] & 0xFF);
    }

    private long read32(int at) {
        return ((long) (value[at] & 0xFF) << 24)
                | ((long) (value[at + 1] & 0xFF) << 16)
                | ((long) (value[at + 2] & 0xFF) << 8)
                | (value[at + 3] & 0xFF);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RouteDistinguisher other)) {
            return false;
        }
        return type == other.type && Arrays.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return 31 * Integer.hashCode(type) + Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "RouteDistinguisher[" + asText() + ']';
    }
}
