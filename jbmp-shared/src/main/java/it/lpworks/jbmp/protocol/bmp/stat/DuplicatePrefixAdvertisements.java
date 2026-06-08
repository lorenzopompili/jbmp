package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 1: number of (known) duplicate prefix advertisements.
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the counter value (unsigned 32-bit conveyed in a long)
 */
public record DuplicatePrefixAdvertisements(long value) implements StatCounter {

    @Override
    public int statType() {
        return 1;
    }
}
