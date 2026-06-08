package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * The MP_REACH_NLRI path attribute (type code 14).
 *
 * <p>See RFC 4760. The next-hop and NLRI fields are retained as raw bytes; decoding
 * them according to the {@code (afi, safi)} pair is performed elsewhere.
 *
 * @param afi      the Address Family Identifier
 * @param safi     the Subsequent Address Family Identifier
 * @param nextHop  the raw next-hop bytes (defensively copied)
 * @param nlri     the raw NLRI bytes (defensively copied)
 */
public record MpReachNlri(int afi, int safi, byte[] nextHop, byte[] nlri) implements PathAttribute {

    /**
     * Validates and defensively copies the raw byte fields.
     */
    public MpReachNlri {
        Objects.requireNonNull(nextHop, "nextHop");
        Objects.requireNonNull(nlri, "nlri");
        nextHop = nextHop.clone();
        nlri = nlri.clone();
    }

    /**
     * Returns a defensive copy of the raw next-hop bytes.
     *
     * @return a fresh copy of the next-hop bytes
     */
    @Override
    public byte[] nextHop() {
        return nextHop.clone();
    }

    /**
     * Returns a defensive copy of the raw NLRI bytes.
     *
     * @return a fresh copy of the NLRI bytes
     */
    @Override
    public byte[] nlri() {
        return nlri.clone();
    }

    @Override
    public int typeCode() {
        return 14;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof MpReachNlri other)) {
            return false;
        }
        return afi == other.afi && safi == other.safi
                && Arrays.equals(nextHop, other.nextHop)
                && Arrays.equals(nlri, other.nlri);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(afi, safi);
        result = 31 * result + Arrays.hashCode(nextHop);
        result = 31 * result + Arrays.hashCode(nlri);
        return result;
    }

    @Override
    public String toString() {
        return "MpReachNlri[afi=" + afi + ", safi=" + safi
                + ", nextHop=" + Arrays.toString(nextHop)
                + ", nlri=" + Arrays.toString(nlri) + ']';
    }
}
