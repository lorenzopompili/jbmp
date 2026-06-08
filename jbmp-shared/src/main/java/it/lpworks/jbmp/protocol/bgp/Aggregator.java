package it.lpworks.jbmp.protocol.bgp;

import java.net.InetAddress;
import java.util.Objects;

/**
 * The AGGREGATOR path attribute (type code 7): the AS and IP address of the speaker
 * that performed route aggregation.
 *
 * <p>See RFC 4271 §5.1.7 (and RFC 6793 for 4-octet AS support). Whether the AS was
 * encoded as 2 or 4 octets is resolved at parse time; the value is always conveyed
 * here as an unsigned 32-bit AS number.
 *
 * @param asn     the aggregating AS number; an unsigned 32-bit value in
 *               {@code [0, 4294967295]}
 * @param address the aggregating speaker's IP address
 */
public record Aggregator(long asn, InetAddress address) implements PathAttribute {

    /** Largest representable unsigned 32-bit value. */
    private static final long MAX_UINT32 = 0xFFFFFFFFL;

    /**
     * Validates the fields.
     */
    public Aggregator {
        if (asn < 0 || asn > MAX_UINT32) {
            throw new IllegalArgumentException(
                    "asn must be a uint32 in [0, " + MAX_UINT32 + "] but was " + asn);
        }
        Objects.requireNonNull(address, "address");
    }

    @Override
    public int typeCode() {
        return 7;
    }
}
