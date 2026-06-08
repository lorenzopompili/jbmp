package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 3: number of updates invalidated due to CLUSTER_LIST loop.
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the counter value (unsigned 32-bit conveyed in a long)
 */
public record InvalidClusterListLoop(long value) implements StatCounter {

    @Override
    public int statType() {
        return 3;
    }
}
