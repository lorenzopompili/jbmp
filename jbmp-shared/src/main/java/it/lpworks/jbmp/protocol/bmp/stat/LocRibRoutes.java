package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * Statistic type 8: number of routes in the Loc-RIB (a 64-bit gauge).
 *
 * <p>See RFC 7854 §4.8.
 *
 * @param value the gauge value (unsigned 64-bit conveyed in a long; values with
 *              the high bit set appear negative when interpreted as signed)
 */
public record LocRibRoutes(long value) implements StatCounter {

    @Override
    public int statType() {
        return 8;
    }
}
