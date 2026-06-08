package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * An Ethernet VPN (EVPN) NLRI route.
 *
 * <p>See RFC 7432 §7. An EVPN NLRI is framed as a 1-octet Route Type, a 1-octet
 * Length and a type-specific Route Type Specific field. This record preserves that
 * type-specific field verbatim in {@link #raw()} to guarantee zero data loss; the
 * five defined route types (RFC 7432 §7.1–§7.5) are:
 * <ul>
 *   <li>1 — Ethernet Auto-Discovery (A-D) route;</li>
 *   <li>2 — MAC/IP Advertisement route;</li>
 *   <li>3 — Inclusive Multicast Ethernet Tag route;</li>
 *   <li>4 — Ethernet Segment route;</li>
 *   <li>5 — IP Prefix route (RFC 9136).</li>
 * </ul>
 *
 * <p>The interior fields are tightly bit-packed and route-type dependent; this model
 * exposes only the leading 8-octet Route Distinguisher, which is present at the same
 * offset for every standardised route type and can therefore be parsed reliably. All
 * remaining structure stays available through {@link #raw()}.
 *
 * <p>The AFI is {@link AddressFamily#AFI_L2VPN} (25) and the SAFI is
 * {@link AddressFamily#SAFI_EVPN} (70).
 *
 * @param routeType the EVPN Route Type (RFC 7432 §7)
 * @param raw       the type-specific Route Type Specific field (defensively copied)
 */
public record EvpnRoute(int routeType, byte[] raw) implements Nlri {

    /**
     * Validates and defensively copies the raw bytes.
     */
    public EvpnRoute {
        Objects.requireNonNull(raw, "raw");
        if (routeType < 0 || routeType > 0xFF) {
            throw new IllegalArgumentException(
                    "routeType must be an unsigned 8-bit value in [0, 255] but was " + routeType);
        }
        raw = raw.clone();
    }

    /**
     * Returns a defensive copy of the type-specific bytes.
     *
     * @return a fresh copy of the raw route value
     */
    @Override
    public byte[] raw() {
        return raw.clone();
    }

    /**
     * Returns the leading 8-octet Route Distinguisher when the value field is long
     * enough to contain it.
     *
     * <p>Every standardised EVPN route type begins with an 8-octet RD (RFC 7432 §7).
     * The RD model holds the 6-octet value (octets 2..8 of the wire encoding), with the
     * leading 2 octets supplying the type.
     *
     * @return the Route Distinguisher, or {@code null} when fewer than 8 octets are
     *         present
     */
    public RouteDistinguisher routeDistinguisher() {
        if (raw.length < 8) {
            return null;
        }
        int rdType = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF);
        byte[] rdValue = Arrays.copyOfRange(raw, 2, 8);
        return new RouteDistinguisher(rdType, rdValue);
    }

    /**
     * Returns the AFI for an EVPN route.
     *
     * @return {@link AddressFamily#AFI_L2VPN}
     */
    @Override
    public int afi() {
        return AddressFamily.AFI_L2VPN;
    }

    /**
     * Returns the SAFI for an EVPN route.
     *
     * @return {@link AddressFamily#SAFI_EVPN}
     */
    @Override
    public int safi() {
        return AddressFamily.SAFI_EVPN;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof EvpnRoute other)) {
            return false;
        }
        return routeType == other.routeType && Arrays.equals(raw, other.raw);
    }

    @Override
    public int hashCode() {
        return 31 * Integer.hashCode(routeType) + Arrays.hashCode(raw);
    }

    @Override
    public String toString() {
        return "EvpnRoute[routeType=" + routeType + ", raw=" + Arrays.toString(raw) + ']';
    }
}
