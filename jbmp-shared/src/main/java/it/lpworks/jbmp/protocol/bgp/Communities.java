package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * The COMMUNITIES path attribute (type code 8): a list of raw 32-bit communities.
 *
 * <p>See RFC 1997. Each value is the packed {@code ((asn << 16) | value)} form;
 * see {@link Community#ofRaw(int)} to decode an individual entry.
 *
 * @param values the raw community values (defensively copied)
 */
public record Communities(int[] values) implements PathAttribute {

    /**
     * Validates and defensively copies the value array.
     */
    public Communities {
        Objects.requireNonNull(values, "values");
        values = values.clone();
    }

    /**
     * Returns a defensive copy of the raw community values.
     *
     * @return a fresh copy of the values
     */
    @Override
    public int[] values() {
        return values.clone();
    }

    @Override
    public int typeCode() {
        return 8;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Communities other)) {
            return false;
        }
        return Arrays.equals(values, other.values);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(values);
    }

    @Override
    public String toString() {
        return "Communities[values=" + Arrays.toString(values) + ']';
    }
}
