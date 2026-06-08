package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * An MPLS VPN prefix: a Route Distinguisher, a stack of MPLS labels and an inner
 * IP prefix.
 *
 * <p>See RFC 4364. The AFI is inherited from the inner prefix and the SAFI is
 * {@link AddressFamily#SAFI_MPLS_VPN}.
 *
 * @param rd          the Route Distinguisher
 * @param mplsLabels  the label stack (defensively copied); each label is a 20-bit
 *                    value conveyed in a {@code long}
 * @param prefix      the inner IP prefix
 */
public record VpnPrefix(RouteDistinguisher rd, long[] mplsLabels, IpPrefix prefix) implements Nlri {

    /** Largest representable 20-bit MPLS label. */
    private static final long MAX_LABEL = 0xFFFFFL;

    /**
     * Validates the fields and defensively copies the label stack.
     */
    public VpnPrefix {
        Objects.requireNonNull(rd, "rd");
        Objects.requireNonNull(mplsLabels, "mplsLabels");
        Objects.requireNonNull(prefix, "prefix");
        for (long label : mplsLabels) {
            if (label < 0 || label > MAX_LABEL) {
                throw new IllegalArgumentException(
                        "MPLS label must be a 20-bit value in [0, " + MAX_LABEL
                                + "] but was " + label);
            }
        }
        mplsLabels = mplsLabels.clone();
    }

    /**
     * Returns a defensive copy of the label stack.
     *
     * @return a fresh copy of the MPLS labels
     */
    @Override
    public long[] mplsLabels() {
        return mplsLabels.clone();
    }

    /**
     * Returns the AFI of the inner prefix.
     *
     * @return the inner prefix's AFI
     */
    @Override
    public int afi() {
        return prefix.afi();
    }

    /**
     * Returns the SAFI for a VPN prefix.
     *
     * @return {@link AddressFamily#SAFI_MPLS_VPN}
     */
    @Override
    public int safi() {
        return AddressFamily.SAFI_MPLS_VPN;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof VpnPrefix other)) {
            return false;
        }
        return rd.equals(other.rd)
                && Arrays.equals(mplsLabels, other.mplsLabels)
                && prefix.equals(other.prefix);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(rd, prefix) + Arrays.hashCode(mplsLabels);
    }

    @Override
    public String toString() {
        return "VpnPrefix[rd=" + rd + ", mplsLabels=" + Arrays.toString(mplsLabels)
                + ", prefix=" + prefix + ']';
    }
}
