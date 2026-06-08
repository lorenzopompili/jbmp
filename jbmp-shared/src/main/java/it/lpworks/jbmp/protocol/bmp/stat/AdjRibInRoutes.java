package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 7: number of routes in the Adj-RIBs-In (a 64-bit gauge).
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the gauge value (unsigned 64-bit conveyed in a long; values with
 *              the high bit set appear negative when interpreted as signed)
 */
public record AdjRibInRoutes(long value) implements StatCounter {

    @Override
    public int statType() {
        return 7;
    }
}
