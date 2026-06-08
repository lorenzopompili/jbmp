package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 13: number of duplicate update messages received.
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the counter value (unsigned 32-bit conveyed in a long)
 */
public record DuplicateUpdates(long value) implements StatCounter {

    @Override
    public int statType() {
        return 13;
    }
}
