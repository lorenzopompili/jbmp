package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 0: number of prefixes rejected by inbound policy.
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the counter value (unsigned 32-bit conveyed in a long)
 */
public record PrefixesRejected(long value) implements StatCounter {

    @Override
    public int statType() {
        return 0;
    }
}
