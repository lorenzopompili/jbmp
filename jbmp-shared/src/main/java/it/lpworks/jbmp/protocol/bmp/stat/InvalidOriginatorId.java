package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 5: number of updates invalidated due to ORIGINATOR_ID.
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the counter value (unsigned 32-bit conveyed in a long)
 */
public record InvalidOriginatorId(long value) implements StatCounter {

    @Override
    public int statType() {
        return 5;
    }
}
