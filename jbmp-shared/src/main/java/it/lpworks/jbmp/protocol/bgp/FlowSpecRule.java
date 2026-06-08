package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A Flow Specification NLRI rule.
 *
 * <p>See RFC 8955. A Flow Specification rule is an ordered list of components that
 * jointly define a traffic flow (RFC 8955 §4.2). For the VPN variant (SAFI 134,
 * RFC 8955 §7 / RFC 9117) the rule additionally carries a leading 8-octet Route
 * Distinguisher, exposed here through {@link #routeDistinguisher()}.
 *
 * <p>The full on-wire rule body (excluding the NLRI length prefix) is preserved in
 * {@link #raw()} to guarantee zero data loss even when a component cannot be
 * delimited; in that case the trailing, undecodable bytes are captured as a single
 * component so no information is dropped.
 *
 * @param safi       {@link AddressFamily#SAFI_FLOWSPEC} (133) or
 *                   {@link AddressFamily#SAFI_FLOWSPEC_VPN} (134)
 * @param raw        the rule body bytes, including any RD (defensively copied)
 * @param components the decoded components in wire order (defensively copied)
 */
public record FlowSpecRule(int safi, byte[] raw, List<FlowSpecComponent> components) implements Nlri {

    /**
     * Validates the fields and defensively copies the mutable inputs.
     */
    public FlowSpecRule {
        Objects.requireNonNull(raw, "raw");
        Objects.requireNonNull(components, "components");
        raw = raw.clone();
        components = List.copyOf(components);
    }

    /**
     * Returns a defensive copy of the raw rule body.
     *
     * @return a fresh copy of the rule bytes
     */
    @Override
    public byte[] raw() {
        return raw.clone();
    }

    /**
     * Returns the leading 8-octet Route Distinguisher for VPN Flow Specification
     * rules.
     *
     * <p>Only meaningful when {@link #safi()} is {@link AddressFamily#SAFI_FLOWSPEC_VPN}
     * (RFC 8955 §7); for the non-VPN variant, or when the body is too short to hold an
     * RD, {@code null} is returned.
     *
     * @return the Route Distinguisher, or {@code null} when not applicable
     */
    public RouteDistinguisher routeDistinguisher() {
        if (safi != AddressFamily.SAFI_FLOWSPEC_VPN || raw.length < 8) {
            return null;
        }
        int rdType = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
        byte[] rdValue = Arrays.copyOfRange(raw, 2, 8);
        return new RouteDistinguisher(rdType, rdValue);
    }

    /**
     * Returns the AFI of this rule.
     *
     * <p>Flow Specification is defined for both IPv4 and IPv6; the AFI is not carried in
     * the NLRI body itself but supplied by the enclosing MP attribute. Where the AFI is
     * not separately tracked this defaults to {@link AddressFamily#AFI_IPV4}.
     *
     * @return {@link AddressFamily#AFI_IPV4}
     */
    @Override
    public int afi() {
        return AddressFamily.AFI_IPV4;
    }

    /**
     * Returns the SAFI of this rule.
     *
     * @return the Flow Specification SAFI supplied at construction
     */
    @Override
    public int safi() {
        return safi;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FlowSpecRule other)) {
            return false;
        }
        return safi == other.safi
                && Arrays.equals(raw, other.raw)
                && components.equals(other.components);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(safi, components) + Arrays.hashCode(raw);
    }

    @Override
    public String toString() {
        return "FlowSpecRule[safi=" + safi + ", components=" + components
                + ", raw=" + Arrays.toString(raw) + ']';
    }
}
