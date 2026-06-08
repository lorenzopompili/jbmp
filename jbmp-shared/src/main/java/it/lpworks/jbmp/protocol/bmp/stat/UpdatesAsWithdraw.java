package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 11: number of updates subjected to "treat-as-withdraw" handling.
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the counter value (unsigned 32-bit conveyed in a long)
 */
public record UpdatesAsWithdraw(long value) implements StatCounter {

    @Override
    public int statType() {
        return 11;
    }
}
