package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * A BGP Link-State (BGP-LS) NLRI.
 *
 * <p>See RFC 7752 §3.2. A BGP-LS NLRI is framed as a 2-octet NLRI Type, a 2-octet
 * Total NLRI Length and a type-specific body. The four defined NLRI types
 * (RFC 7752 §3.2) are:
 * <ul>
 *   <li>1 — Node NLRI;</li>
 *   <li>2 — Link NLRI;</li>
 *   <li>3 — IPv4 Topology Prefix NLRI;</li>
 *   <li>4 — IPv6 Topology Prefix NLRI.</li>
 * </ul>
 *
 * <p>The body is a nested set of descriptors and TLVs; it is preserved verbatim in
 * {@link #raw()} to guarantee zero data loss. The AFI is
 * {@link AddressFamily#AFI_BGP_LS} (16388) and the SAFI is
 * {@link AddressFamily#SAFI_BGP_LS} (71) or {@link AddressFamily#SAFI_BGP_LS_VPN}
 * (72).
 *
 * @param nlriType the 2-octet NLRI Type (RFC 7752 §3.2)
 * @param raw      the type-specific NLRI body (defensively copied)
 */
public record LinkStateNlri(int nlriType, byte[] raw) implements Nlri {

    /**
     * Validates and defensively copies the raw bytes.
     */
    public LinkStateNlri {
        Objects.requireNonNull(raw, "raw");
        if (nlriType < 0 || nlriType > 0xFFFF) {
            throw new IllegalArgumentException(
                    "nlriType must be an unsigned 16-bit value in [0, 65535] but was " + nlriType);
        }
        raw = raw.clone();
    }

    /**
     * Returns a defensive copy of the NLRI body.
     *
     * @return a fresh copy of the raw bytes
     */
    @Override
    public byte[] raw() {
        return raw.clone();
    }

    /**
     * Returns the AFI for a BGP-LS NLRI.
     *
     * @return {@link AddressFamily#AFI_BGP_LS}
     */
    @Override
    public int afi() {
        return AddressFamily.AFI_BGP_LS;
    }

    /**
     * Returns the SAFI for a BGP-LS NLRI.
     *
     * @return {@link AddressFamily#SAFI_BGP_LS}
     */
    @Override
    public int safi() {
        return AddressFamily.SAFI_BGP_LS;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof LinkStateNlri other)) {
            return false;
        }
        return nlriType == other.nlriType && Arrays.equals(raw, other.raw);
    }

    @Override
    public int hashCode() {
        return 31 * Integer.hashCode(nlriType) + Arrays.hashCode(raw);
    }

    @Override
    public String toString() {
        return "LinkStateNlri[nlriType=" + nlriType + ", raw=" + Arrays.toString(raw) + ']';
    }
}
