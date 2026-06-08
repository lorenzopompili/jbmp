package it.lpworks.jbmp.protocol.bgp;

import java.util.Objects;

/**
 * An NLRI carried with a BGP ADD-PATH Path Identifier.
 *
 * <p>See RFC 7911 §3. When ADD-PATH is in effect for an {@code (afi, safi)} pair,
 * every NLRI on the wire is preceded by a 4-octet Path Identifier that allows a
 * speaker to advertise multiple paths for the same prefix. This record is a thin,
 * immutable wrapper that pairs the decoded inner {@link Nlri} with its Path
 * Identifier; the AFI and SAFI are delegated to the wrapped NLRI.
 *
 * @param pathId the 4-octet Path Identifier, conveyed as an unsigned value in a
 *               {@code long} (RFC 7911 §3)
 * @param nlri   the wrapped address-family NLRI (never {@code null})
 */
public record AddPathNlri(long pathId, Nlri nlri) implements Nlri {

    /**
     * Validates the wrapped NLRI and Path Identifier range.
     */
    public AddPathNlri {
        Objects.requireNonNull(nlri, "nlri");
        if (pathId < 0 || pathId > 0xFFFFFFFFL) {
            throw new IllegalArgumentException(
                    "pathId must be an unsigned 32-bit value in [0, 4294967295] but was " + pathId);
        }
    }

    /**
     * Returns the AFI of the wrapped NLRI.
     *
     * @return the inner NLRI's AFI (see {@link AddressFamily})
     */
    @Override
    public int afi() {
        return nlri.afi();
    }

    /**
     * Returns the SAFI of the wrapped NLRI.
     *
     * @return the inner NLRI's SAFI (see {@link AddressFamily})
     */
    @Override
    public int safi() {
        return nlri.safi();
    }
}
