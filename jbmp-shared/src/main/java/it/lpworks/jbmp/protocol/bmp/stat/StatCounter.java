package it.lpworks.jbmp.protocol.bmp.stat;

/**
 * A single statistic carried inside a Statistics Report message.
 *
 * <p>Each counter is a {@code (type, value)} pair. The statistic types and their
 * value widths are defined in RFC 7854 §4.8. Known types are modelled as distinct
 * record implementations; any type not modelled here is captured by
 * {@link UnknownStat}.
 */
public sealed interface StatCounter
        permits PrefixesRejected,
                DuplicatePrefixAdvertisements,
                DuplicateWithdraws,
                InvalidClusterListLoop,
                InvalidAsPathLoop,
                InvalidOriginatorId,
                InvalidAsConfedLoop,
                AdjRibInRoutes,
                LocRibRoutes,
                UpdatesAsWithdraw,
                PrefixesAsWithdraw,
                DuplicateUpdates,
                UnknownStat {

    /**
     * Returns the counter value.
     *
     * @return the value (a 32-bit counter is returned in the low bits of the long;
     *         64-bit gauges occupy the full range)
     */
    long value();

    /**
     * Returns the on-wire statistic type code.
     *
     * @return the unsigned 16-bit statistic type
     */
    int statType();
}
