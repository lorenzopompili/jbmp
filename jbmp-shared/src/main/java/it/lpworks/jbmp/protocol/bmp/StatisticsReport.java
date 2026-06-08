package it.lpworks.jbmp.protocol.bmp;

import it.lpworks.jbmp.protocol.bmp.stat.StatCounter;

import java.util.List;
import java.util.Objects;

/**
 * A BMP Statistics Report message.
 *
 * <p>See RFC 7854 §4.8. Periodically conveys a set of per-peer counters and gauges.
 *
 * @param peerHeader the per-peer header
 * @param counters   the reported statistic counters (immutable copy)
 */
public record StatisticsReport(PerPeerHeader peerHeader, List<StatCounter> counters)
        implements BmpMessage {

    /**
     * Validates and defensively copies the counter list.
     */
    public StatisticsReport {
        Objects.requireNonNull(peerHeader, "peerHeader");
        Objects.requireNonNull(counters, "counters");
        counters = List.copyOf(counters);
    }

    @Override
    public BmpMessageType type() {
        return BmpMessageType.STATISTICS_REPORT;
    }
}
