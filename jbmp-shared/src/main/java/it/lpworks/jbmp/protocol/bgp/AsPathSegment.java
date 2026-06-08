package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * A single AS_PATH segment: a type plus an ordered list of AS numbers.
 *
 * <p>See RFC 4271 §4.3 (and RFC 5065 for confederation segments). Each ASN is an
 * unsigned 32-bit value conveyed in a {@code long}; 2-byte AS encodings are widened
 * to 4 bytes at parse time.
 *
 * @param type the segment type
 * @param asns the AS numbers, in wire order (defensively copied); each in
 *             {@code [0, 4294967295]}
 */
public record AsPathSegment(AsPathSegmentType type, long[] asns) {

    /** Largest representable unsigned 32-bit AS number. */
    private static final long MAX_UINT32 = 0xFFFFFFFFL;

    /**
     * Validates the fields and defensively copies the ASN array.
     */
    public AsPathSegment {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(asns, "asns");
        for (long asn : asns) {
            if (asn < 0 || asn > MAX_UINT32) {
                throw new IllegalArgumentException(
                        "ASN must be a uint32 in [0, " + MAX_UINT32 + "] but was " + asn);
            }
        }
        asns = asns.clone();
    }

    /**
     * Returns a defensive copy of the ASN array.
     *
     * @return a fresh copy of the ASNs in wire order
     */
    @Override
    public long[] asns() {
        return asns.clone();
    }

    /**
     * Returns the number of ASNs in this segment without copying the backing array.
     *
     * @return the ASN count
     */
    int asnCount() {
        return asns.length;
    }

    /**
     * Returns the ASN at the given index without copying the backing array.
     *
     * @param index the index, in {@code [0, asnCount())}
     * @return the ASN at that index
     */
    long asnAt(int index) {
        return asns[index];
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AsPathSegment other)) {
            return false;
        }
        return type == other.type && Arrays.equals(asns, other.asns);
    }

    @Override
    public int hashCode() {
        return 31 * type.hashCode() + Arrays.hashCode(asns);
    }

    @Override
    public String toString() {
        return "AsPathSegment[type=" + type + ", asns=" + Arrays.toString(asns) + ']';
    }
}
