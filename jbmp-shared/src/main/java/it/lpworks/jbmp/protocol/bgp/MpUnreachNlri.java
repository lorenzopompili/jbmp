package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * The MP_UNREACH_NLRI path attribute (type code 15).
 *
 * <p>See RFC 4760. The withdrawn NLRI is retained as raw bytes; decoding it according
 * to the {@code (afi, safi)} pair is performed elsewhere. An empty withdrawn-NLRI for
 * {@code (afi, safi)} is also the RFC 4724 End-of-RIB marker.
 *
 * @param afi           the Address Family Identifier
 * @param safi          the Subsequent Address Family Identifier
 * @param withdrawnNlri the raw withdrawn-NLRI bytes (defensively copied)
 */
public record MpUnreachNlri(int afi, int safi, byte[] withdrawnNlri) implements PathAttribute {

    /**
     * Validates and defensively copies the raw byte field.
     */
    public MpUnreachNlri {
        Objects.requireNonNull(withdrawnNlri, "withdrawnNlri");
        withdrawnNlri = withdrawnNlri.clone();
    }

    /**
     * Returns a defensive copy of the raw withdrawn-NLRI bytes.
     *
     * @return a fresh copy of the withdrawn-NLRI bytes
     */
    @Override
    public byte[] withdrawnNlri() {
        return withdrawnNlri.clone();
    }

    @Override
    public int typeCode() {
        return 15;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof MpUnreachNlri other)) {
            return false;
        }
        return afi == other.afi && safi == other.safi
                && Arrays.equals(withdrawnNlri, other.withdrawnNlri);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(afi, safi) + Arrays.hashCode(withdrawnNlri);
    }

    @Override
    public String toString() {
        return "MpUnreachNlri[afi=" + afi + ", safi=" + safi
                + ", withdrawnNlri=" + Arrays.toString(withdrawnNlri) + ']';
    }
}
