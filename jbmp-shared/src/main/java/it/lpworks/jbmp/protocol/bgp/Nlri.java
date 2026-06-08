package it.lpworks.jbmp.protocol.bgp;

/**
 * Network Layer Reachability Information: a reachability/withdrawal entry described
 * by its address family.
 *
 * <p>See RFC 4271 §4.3 and RFC 4760. This interface is intentionally left open
 * (not sealed) because the set of address families is open and may be extended by
 * additional implementations.
 */
public interface Nlri {

    /**
     * Returns the Address Family Identifier of this NLRI.
     *
     * @return the AFI (see {@link AddressFamily})
     */
    int afi();

    /**
     * Returns the Subsequent Address Family Identifier of this NLRI.
     *
     * @return the SAFI (see {@link AddressFamily})
     */
    int safi();
}
