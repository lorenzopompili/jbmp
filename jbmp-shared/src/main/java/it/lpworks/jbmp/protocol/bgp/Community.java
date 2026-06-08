package it.lpworks.jbmp.protocol.bgp;

/**
 * A standard BGP community: a 16-bit AS number paired with a 16-bit value.
 *
 * <p>See RFC 1997. On the wire a community is a single 32-bit value whose high half
 * is the AS number and low half the value.
 *
 * @param asn   the high 16 bits, in {@code [0, 65535]}
 * @param value the low 16 bits, in {@code [0, 65535]}
 */
public record Community(int asn, int value) {

    /** Maximum representable unsigned 16-bit value. */
    private static final int MAX_UINT16 = 0xFFFF;

    /**
     * Validates that both halves are unsigned 16-bit values.
     */
    public Community {
        if (asn < 0 || asn > MAX_UINT16) {
            throw new IllegalArgumentException(
                    "asn must be a uint16 in [0, " + MAX_UINT16 + "] but was " + asn);
        }
        if (value < 0 || value > MAX_UINT16) {
            throw new IllegalArgumentException(
                    "value must be a uint16 in [0, " + MAX_UINT16 + "] but was " + value);
        }
    }

    /**
     * Returns the packed 32-bit on-wire representation {@code ((asn << 16) | value)}.
     *
     * @return the raw community value
     */
    public int raw() {
        return (asn << 16) | value;
    }

    /**
     * Constructs a community from its packed 32-bit on-wire representation.
     *
     * @param raw the raw 32-bit community value
     * @return the decoded community
     */
    public static Community ofRaw(int raw) {
        return new Community((raw >>> 16) & 0xFFFF, raw & 0xFFFF);
    }
}
