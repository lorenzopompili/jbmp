package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * A Segment Routing Policy NLRI.
 *
 * <p>See draft-ietf-idr-segment-routing-te-policy (BGP SR Policy SAFI 73). The NLRI
 * encodes a distinguisher, a policy colour and an endpoint address. Because the SR
 * Policy encoding is still evolving and AFI-dependent (the endpoint is 4 octets for
 * IPv4 and 16 octets for IPv6), this model preserves the NLRI verbatim in
 * {@link #raw()} to guarantee zero data loss while exposing the leading 1-octet NLRI
 * length where present.
 *
 * <p>The SAFI is {@link AddressFamily#SAFI_SR_POLICY} (73).
 *
 * @param raw the raw NLRI bytes (defensively copied)
 */
public record SrPolicyNlri(byte[] raw) implements Nlri {

    /**
     * Validates and defensively copies the raw bytes.
     */
    public SrPolicyNlri {
        Objects.requireNonNull(raw, "raw");
        raw = raw.clone();
    }

    /**
     * Returns a defensive copy of the raw NLRI bytes.
     *
     * @return a fresh copy of the raw bytes
     */
    @Override
    public byte[] raw() {
        return raw.clone();
    }

    /**
     * Returns the AFI of this NLRI.
     *
     * <p>SR Policy is defined for both IPv4 and IPv6 endpoints; the AFI is supplied by
     * the enclosing MP attribute rather than the NLRI body. Where the AFI is not
     * separately tracked this defaults to {@link AddressFamily#AFI_IPV4}.
     *
     * @return {@link AddressFamily#AFI_IPV4}
     */
    @Override
    public int afi() {
        return AddressFamily.AFI_IPV4;
    }

    /**
     * Returns the SAFI for an SR Policy NLRI.
     *
     * @return {@link AddressFamily#SAFI_SR_POLICY}
     */
    @Override
    public int safi() {
        return AddressFamily.SAFI_SR_POLICY;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SrPolicyNlri other)) {
            return false;
        }
        return Arrays.equals(raw, other.raw);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(raw);
    }

    @Override
    public String toString() {
        return "SrPolicyNlri[raw=" + Arrays.toString(raw) + ']';
    }
}
