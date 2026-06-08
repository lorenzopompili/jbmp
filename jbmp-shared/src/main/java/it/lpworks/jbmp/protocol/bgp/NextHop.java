package it.lpworks.jbmp.protocol.bgp;

import java.net.InetAddress;
import java.util.Objects;

/**
 * The NEXT_HOP path attribute (type code 3).
 *
 * <p>See RFC 4271 §5.1.3.
 *
 * @param address the next-hop IP address
 */
public record NextHop(InetAddress address) implements PathAttribute {

    /**
     * Validates the field.
     */
    public NextHop {
        Objects.requireNonNull(address, "address");
    }

    @Override
    public int typeCode() {
        return 3;
    }
}
