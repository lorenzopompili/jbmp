package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * A catch-all NLRI that preserves the raw on-wire bytes for any address family not
 * otherwise modelled.
 *
 * <p>See RFC 4760 for the AFI/SAFI framing. The {@code data} holds the family-specific
 * NLRI encoding verbatim.
 *
 * @param afi  the Address Family Identifier
 * @param safi the Subsequent Address Family Identifier
 * @param data the raw NLRI bytes (defensively copied)
 */
public record RawNlri(int afi, int safi, byte[] data) implements Nlri {

    /**
     * Validates the fields and defensively copies the raw bytes.
     */
    public RawNlri {
        Objects.requireNonNull(data, "data");
        data = data.clone();
    }

    /**
     * Returns a defensive copy of the raw NLRI bytes.
     *
     * @return a fresh copy of the data
     */
    @Override
    public byte[] data() {
        return data.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RawNlri other)) {
            return false;
        }
        return afi == other.afi && safi == other.safi && Arrays.equals(data, other.data);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(afi, safi) + Arrays.hashCode(data);
    }

    @Override
    public String toString() {
        return "RawNlri[afi=" + afi + ", safi=" + safi + ", data=" + Arrays.toString(data) + ']';
    }
}
