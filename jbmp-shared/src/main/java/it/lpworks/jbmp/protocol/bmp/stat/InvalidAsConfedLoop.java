package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 6: number of updates invalidated due to AS_CONFED loop.
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the counter value (unsigned 32-bit conveyed in a long)
 */
public record InvalidAsConfedLoop(long value) implements StatCounter {

    @Override
    public int statType() {
        return 6;
    }
}
