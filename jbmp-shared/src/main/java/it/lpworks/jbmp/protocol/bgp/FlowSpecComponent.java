package it.lpworks.jbmp.protocol.bgp;

import java.util.Arrays;
import java.util.Objects;

/**
 * A single Flow Specification component within a {@link FlowSpecRule}.
 *
 * <p>See RFC 8955 §4.2. A Flow Specification NLRI is an ordered list of components,
 * each introduced by a 1-octet component type followed by a type-specific encoding
 * (a destination/source prefix for types 1 and 2, or a list of {operator, value}
 * pairs for the numeric-match types). This record stores the component type together
 * with its value bytes verbatim to preserve fidelity for every component type,
 * including types this collector does not interpret.
 *
 * @param type the 1-octet component type (RFC 8955 §4.2.1)
 * @param raw  the type-specific value bytes (defensively copied)
 */
public record FlowSpecComponent(int type, byte[] raw) {

    /**
     * Validates and defensively copies the value bytes.
     */
    public FlowSpecComponent {
        Objects.requireNonNull(raw, "raw");
        if (type < 0 || type > 0xFF) {
            throw new IllegalArgumentException(
                    "type must be an unsigned 8-bit value in [0, 255] but was " + type);
        }
        raw = raw.clone();
    }

    /**
     * Returns a defensive copy of the value bytes.
     *
     * @return a fresh copy of the component value
     */
    @Override
    public byte[] raw() {
        return raw.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FlowSpecComponent other)) {
            return false;
        }
        return type == other.type && Arrays.equals(raw, other.raw);
    }

    @Override
    public int hashCode() {
        return 31 * Integer.hashCode(type) + Arrays.hashCode(raw);
    }

    @Override
    public String toString() {
        return "FlowSpecComponent[type=" + type + ", raw=" + Arrays.toString(raw) + ']';
    }
}
