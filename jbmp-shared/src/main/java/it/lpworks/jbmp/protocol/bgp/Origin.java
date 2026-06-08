package it.lpworks.jbmp.protocol.bgp;

import java.util.Objects;

/**
 * The ORIGIN path attribute (type code 1).
 *
 * <p>See RFC 4271 §5.1.1.
 *
 * @param value the origin type
 */
public record Origin(OriginType value) implements PathAttribute {

    /**
     * Validates the field.
     */
    public Origin {
        Objects.requireNonNull(value, "value");
    }

    @Override
    public int typeCode() {
        return 1;
    }
}
