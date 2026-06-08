package it.lpworks.jbmp.consumer.store;

import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * The identity of a single entry in the current routing-state ({@code rib_state}) view: the
 * monitored {@code peerId} together with the network {@code prefix} (its bytes and length, which
 * the stored {@code cidr} encodes together).
 *
 * <p>The view keeps at most one row per advertised prefix per peer, matching the reference
 * relational model whose primary key is {@code (peer_id, prefix)}. An announce upserts the row
 * with this key; a withdraw removes it. The ADD-PATH (RFC 7911) Path Identifier is deliberately
 * <em>not</em> part of the key, so a later path to the same prefix from one peer replaces the
 * earlier one, exactly as the reference projection does.
 *
 * @param peerId       the deterministic identity of the monitored peer (never {@code null})
 * @param prefix       the network prefix bytes (defensively copied; never {@code null})
 * @param prefixLength the prefix length in bits
 */
public record RibKey(UUID peerId, byte[] prefix, int prefixLength) {

    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * Canonicalises the key: requires a non-null peer identity and defensively copies the prefix
     * bytes (substituting an empty array for {@code null}).
     *
     * @throws NullPointerException if {@code peerId} is {@code null}
     */
    public RibKey {
        Objects.requireNonNull(peerId, "peerId");
        prefix = (prefix == null || prefix.length == 0) ? EMPTY_BYTES : prefix.clone();
    }

    /**
     * Derives the routing-state key from a route-monitoring message.
     *
     * @param msg the route-monitoring message (never {@code null})
     * @return the corresponding routing-state key
     */
    public static RibKey of(RouteMonitorMessage msg) {
        return new RibKey(msg.header().peerId(), msg.prefix(), msg.prefixLength());
    }

    /** @return a defensive copy of the prefix bytes */
    @Override
    public byte[] prefix() {
        return prefix.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RibKey other)) {
            return false;
        }
        return prefixLength == other.prefixLength
                && peerId.equals(other.peerId)
                && Arrays.equals(prefix, other.prefix);
    }

    @Override
    public int hashCode() {
        int result = peerId.hashCode();
        result = 31 * result + Arrays.hashCode(prefix);
        result = 31 * result + prefixLength;
        return result;
    }

    @Override
    public String toString() {
        return "RibKey[peerId=" + peerId
                + ", prefix=" + Arrays.toString(prefix)
                + ", prefixLength=" + prefixLength + ']';
    }
}
