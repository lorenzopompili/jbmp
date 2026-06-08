package it.lpworks.jbmp.wire;

import java.util.Arrays;

/**
 * One segment of a decoded BGP AS_PATH attribute (RFC 4271, Section 5.1.2; four-octet
 * ASNs per RFC 6793).
 *
 * <p>A segment groups a run of autonomous-system numbers together with the segment type
 * that governs their ordering semantics. Confederation segment types are defined by
 * RFC 5065.
 *
 * @param segmentType the segment type: {@code 1}=AS_SET, {@code 2}=AS_SEQUENCE,
 *                    {@code 3}=AS_CONFED_SEQUENCE, {@code 4}=AS_CONFED_SET
 * @param asns        the autonomous-system numbers, each an unsigned 32-bit value
 *                    conveyed in a {@code long}; defensively copied
 */
public record AsPathSegmentInfo(int segmentType, long[] asns) {

    /**
     * Defensively copies the ASN array, substituting an empty array for {@code null}.
     */
    public AsPathSegmentInfo {
        asns = (asns == null) ? new long[0] : asns.clone();
    }

    /**
     * Returns a defensive copy of the segment's ASNs.
     *
     * @return a fresh array of the autonomous-system numbers
     */
    @Override
    public long[] asns() {
        return asns.clone();
    }

    /**
     * Value equality including element-wise comparison of the ASN array.
     *
     * @param o the object to compare with
     * @return {@code true} if {@code o} is an {@code AsPathSegmentInfo} with the same type
     *         and ASNs
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AsPathSegmentInfo other)) {
            return false;
        }
        return segmentType == other.segmentType && Arrays.equals(asns, other.asns);
    }

    /**
     * Hash code consistent with {@link #equals(Object)} (array-aware).
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        return 31 * segmentType + Arrays.hashCode(asns);
    }

    /**
     * Renders the segment type and ASNs.
     *
     * @return a human-readable representation
     */
    @Override
    public String toString() {
        return "AsPathSegmentInfo[segmentType=" + segmentType
                + ", asns=" + Arrays.toString(asns) + ']';
    }
}
