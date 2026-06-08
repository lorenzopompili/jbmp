package it.lpworks.jbmp.wire;

import java.util.Collections;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * An enriched statistics snapshot derived from a BMP Statistics Report (RFC 7854,
 * Section 4.8).
 *
 * <p>A BMP Statistics Report carries a set of (Stat Type, value) counters. They are kept
 * here in a {@link SortedMap} keyed by Stat Type so that encoding order is deterministic
 * regardless of how the counters were collected, which keeps the Kafka wire image stable
 * for identical inputs.
 *
 * <p>This record is immutable: the supplied map is copied into an unmodifiable
 * {@link TreeMap} on construction.
 *
 * @param header   the provenance header (never {@code null})
 * @param counters the Stat Type to value map (RFC 7854 §4.8); copied and sorted by key
 */
public record StatsReportMessage(MessageHeader header, SortedMap<Integer, Long> counters) {

    /**
     * Copies the counters into an unmodifiable, key-sorted map for deterministic encoding.
     *
     * @throws NullPointerException if {@code header} is {@code null}, or if the supplied
     *                              map contains a {@code null} key or value
     */
    public StatsReportMessage {
        Objects.requireNonNull(header, "header");
        TreeMap<Integer, Long> sorted = new TreeMap<>();
        if (counters != null) {
            for (var entry : counters.entrySet()) {
                Objects.requireNonNull(entry.getKey(), "counter statType");
                Objects.requireNonNull(entry.getValue(), "counter value");
                sorted.put(entry.getKey(), entry.getValue());
            }
        }
        counters = Collections.unmodifiableSortedMap(sorted);
    }
}
