package it.lpworks.jbmp.protocol.bmp;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * The per-peer header that precedes most BMP message bodies.
 *
 * <p>See RFC 7854 §4.2. The header carries the peer type and flags, an 8-byte
 * peer distinguisher (a Route Distinguisher for RD/Local instance peers, zero
 * otherwise), the peer address, its Autonomous System number, its BGP Identifier
 * and the timestamp at which the encapsulated event occurred.
 *
 * @param peerType      the peer type
 * @param flags         the decoded per-peer flags
 * @param distinguisher the 8-byte peer distinguisher (defensively copied)
 * @param address       the peer IP address (IPv4 or IPv6 per the V flag)
 * @param peerAsn       the peer AS number; an unsigned 32-bit value in {@code [0, 4294967295]}
 * @param bgpId         the peer BGP Identifier (a 4-byte value modelled as an IPv4 address)
 * @param timestamp     the event timestamp
 */
public record PerPeerHeader(
        PeerType peerType,
        PeerFlags flags,
        byte[] distinguisher,
        InetAddress address,
        long peerAsn,
        Inet4Address bgpId,
        Instant timestamp) {

    /** Largest representable unsigned 32-bit AS number. */
    private static final long MAX_UINT32 = 0xFFFFFFFFL;

    /** Required length of the peer distinguisher field. */
    private static final int DISTINGUISHER_LEN = 8;

    /**
     * Validates the fields and defensively copies the distinguisher.
     */
    public PerPeerHeader {
        Objects.requireNonNull(peerType, "peerType");
        Objects.requireNonNull(flags, "flags");
        Objects.requireNonNull(distinguisher, "distinguisher");
        Objects.requireNonNull(address, "address");
        Objects.requireNonNull(bgpId, "bgpId");
        Objects.requireNonNull(timestamp, "timestamp");
        if (distinguisher.length != DISTINGUISHER_LEN) {
            throw new IllegalArgumentException(
                    "distinguisher must be exactly " + DISTINGUISHER_LEN
                            + " bytes but was " + distinguisher.length);
        }
        if (peerAsn < 0 || peerAsn > MAX_UINT32) {
            throw new IllegalArgumentException(
                    "peerAsn must be a uint32 in [0, " + MAX_UINT32 + "] but was " + peerAsn);
        }
        distinguisher = distinguisher.clone();
    }

    /**
     * Returns a defensive copy of the 8-byte peer distinguisher.
     *
     * @return a fresh copy of the distinguisher
     */
    @Override
    public byte[] distinguisher() {
        return distinguisher.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PerPeerHeader other)) {
            return false;
        }
        return peerAsn == other.peerAsn
                && peerType == other.peerType
                && flags.equals(other.flags)
                && Arrays.equals(distinguisher, other.distinguisher)
                && address.equals(other.address)
                && bgpId.equals(other.bgpId)
                && timestamp.equals(other.timestamp);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(peerType, flags, address, peerAsn, bgpId, timestamp);
        result = 31 * result + Arrays.hashCode(distinguisher);
        return result;
    }

    @Override
    public String toString() {
        return "PerPeerHeader[peerType=" + peerType
                + ", flags=" + flags
                + ", distinguisher=" + Arrays.toString(distinguisher)
                + ", address=" + address
                + ", peerAsn=" + peerAsn
                + ", bgpId=" + bgpId
                + ", timestamp=" + timestamp + ']';
    }
}
