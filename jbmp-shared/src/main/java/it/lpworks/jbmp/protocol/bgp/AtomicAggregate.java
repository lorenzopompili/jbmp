package it.lpworks.jbmp.protocol.bgp;

/**
 * The ATOMIC_AGGREGATE path attribute (type code 6).
 *
 * <p>See RFC 4271 §5.1.6. This attribute has no value; its mere presence is the
 * signal.
 */
public record AtomicAggregate() implements PathAttribute {

    @Override
    public int typeCode() {
        return 6;
    }
}
