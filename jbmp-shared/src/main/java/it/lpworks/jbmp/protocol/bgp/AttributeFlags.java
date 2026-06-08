package it.lpworks.jbmp.protocol.bgp;

/**
 * The high-order flag bits of a BGP path attribute's flags octet.
 *
 * <p>Per RFC 4271 §4.3 the attribute flags octet's high-order bits are:
 * <ul>
 *   <li>bit 7 ({@code 0x80}, O): optional when set, well-known when clear;</li>
 *   <li>bit 6 ({@code 0x40}, T): transitive when set;</li>
 *   <li>bit 5 ({@code 0x20}, P): partial when set;</li>
 *   <li>bit 4 ({@code 0x10}, E): extended length (2-octet length field) when set.</li>
 * </ul>
 *
 * @param optional       the O flag: the attribute is optional
 * @param transitive     the T flag: the attribute is transitive
 * @param partial        the P flag: the attribute is partial
 * @param extendedLength the E flag: the length field is two octets
 */
public record AttributeFlags(boolean optional, boolean transitive, boolean partial,
                             boolean extendedLength) {

    private static final int FLAG_OPTIONAL = 0x80;
    private static final int FLAG_TRANSITIVE = 0x40;
    private static final int FLAG_PARTIAL = 0x20;
    private static final int FLAG_EXTENDED_LENGTH = 0x10;

    /**
     * Decodes a flags octet into its component bits.
     *
     * @param b the flags octet (only the documented high-order bits are interpreted)
     * @return the decoded flags
     */
    public static AttributeFlags fromByte(int b) {
        return new AttributeFlags(
                (b & FLAG_OPTIONAL) != 0,
                (b & FLAG_TRANSITIVE) != 0,
                (b & FLAG_PARTIAL) != 0,
                (b & FLAG_EXTENDED_LENGTH) != 0);
    }
}
