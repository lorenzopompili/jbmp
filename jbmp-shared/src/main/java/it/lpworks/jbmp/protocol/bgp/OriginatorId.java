package it.lpworks.jbmp.protocol.bgp;

import java.net.Inet4Address;
import java.util.Objects;

/**
 * The ORIGINATOR_ID path attribute (type code 9): the BGP Identifier of the route
 * reflector's client that originated the route.
 *
 * <p>See RFC 4456. The value is a 4-octet BGP Identifier modelled as an IPv4 address.
 *
 * @param id the originating speaker's BGP Identifier
 */
public record OriginatorId(Inet4Address id) implements PathAttribute {

    /**
     * Validates the field.
     */
    public OriginatorId {
        Objects.requireNonNull(id, "id");
    }

    @Override
    public int typeCode() {
        return 9;
    }
}
