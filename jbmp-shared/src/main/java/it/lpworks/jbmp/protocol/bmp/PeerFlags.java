package it.lpworks.jbmp.protocol.bmp;

/**
 * The per-peer header flags byte, decoded into its individual bits.
 *
 * <p>Per RFC 7854 §4.2 the high-order bits of the flags octet are:
 * <ul>
 *   <li>bit 7 ({@code 0x80}, V): the peer address is IPv6 when set, IPv4 when clear;</li>
 *   <li>bit 6 ({@code 0x40}, L): routes are post-policy Adj-RIB-In when set, pre-policy when clear;</li>
 *   <li>bit 5 ({@code 0x20}, A): the AS_PATH is encoded with 2-byte ASNs when set, 4-byte when clear.</li>
 * </ul>
 *
 * @param ipv6           the V flag: peer address family is IPv6
 * @param postPolicy     the L flag: routes are post-policy
 * @param twoByteAsPath  the A flag: AS_PATH uses 2-byte ASNs
 */
public record PeerFlags(boolean ipv6, boolean postPolicy, boolean twoByteAsPath) {

    /** Bit mask for the V (IPv6) flag. */
    private static final int FLAG_V = 0x80;
    /** Bit mask for the L (post-policy) flag. */
    private static final int FLAG_L = 0x40;
    /** Bit mask for the A (2-byte AS_PATH) flag. */
    private static final int FLAG_A = 0x20;

    /**
     * Decodes a flags octet into its component bits.
     *
     * @param b the flags octet (only the documented high-order bits are interpreted)
     * @return the decoded flags
     */
    public static PeerFlags fromByte(int b) {
        return new PeerFlags((b & FLAG_V) != 0, (b & FLAG_L) != 0, (b & FLAG_A) != 0);
    }
}
