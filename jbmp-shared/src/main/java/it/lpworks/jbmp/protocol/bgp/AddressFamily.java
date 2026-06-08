package it.lpworks.jbmp.protocol.bgp;

/**
 * Constants for IANA Address Family Identifiers (AFI) and Subsequent Address Family
 * Identifiers (SAFI) used by BGP multiprotocol extensions.
 *
 * <p>See RFC 4760 for the AFI/SAFI framework; individual values are assigned in the
 * IANA AFI and SAFI registries. This class is a constant holder and cannot be
 * instantiated.
 */
public final class AddressFamily {

    /** AFI: IPv4. */
    public static final int AFI_IPV4 = 1;
    /** AFI: IPv6. */
    public static final int AFI_IPV6 = 2;
    /** AFI: L2VPN. */
    public static final int AFI_L2VPN = 25;
    /** AFI: BGP Link-State. */
    public static final int AFI_BGP_LS = 16388;

    /** SAFI: unicast. */
    public static final int SAFI_UNICAST = 1;
    /** SAFI: multicast. */
    public static final int SAFI_MULTICAST = 2;
    /** SAFI: MPLS-labeled VPN (RFC 4364). */
    public static final int SAFI_MPLS_VPN = 128;
    /** SAFI: Ethernet VPN (RFC 7432). */
    public static final int SAFI_EVPN = 70;
    /** SAFI: Flow Specification (RFC 8955). */
    public static final int SAFI_FLOWSPEC = 133;
    /** SAFI: VPN Flow Specification (RFC 8955). */
    public static final int SAFI_FLOWSPEC_VPN = 134;
    /** SAFI: SR Policy. */
    public static final int SAFI_SR_POLICY = 73;
    /** SAFI: BGP Link-State. */
    public static final int SAFI_BGP_LS = 71;
    /** SAFI: BGP Link-State VPN. */
    public static final int SAFI_BGP_LS_VPN = 72;

    private AddressFamily() {
        // Constant holder; not instantiable.
    }

    /**
     * Returns a human-readable description of an {@code (afi, safi)} pair, naming the
     * recognised values and falling back to the numeric codes otherwise.
     *
     * @param afi  the Address Family Identifier
     * @param safi the Subsequent Address Family Identifier
     * @return a description such as {@code "IPv4/unicast"} or {@code "IPv6/2"}
     */
    public static String describe(int afi, int safi) {
        return describeAfi(afi) + "/" + describeSafi(safi);
    }

    private static String describeAfi(int afi) {
        return switch (afi) {
            case AFI_IPV4 -> "IPv4";
            case AFI_IPV6 -> "IPv6";
            case AFI_L2VPN -> "L2VPN";
            case AFI_BGP_LS -> "BGP-LS";
            default -> Integer.toString(afi);
        };
    }

    private static String describeSafi(int safi) {
        return switch (safi) {
            case SAFI_UNICAST -> "unicast";
            case SAFI_MULTICAST -> "multicast";
            case SAFI_MPLS_VPN -> "mpls-vpn";
            case SAFI_EVPN -> "evpn";
            case SAFI_FLOWSPEC -> "flowspec";
            case SAFI_FLOWSPEC_VPN -> "flowspec-vpn";
            case SAFI_SR_POLICY -> "sr-policy";
            case SAFI_BGP_LS -> "bgp-ls";
            case SAFI_BGP_LS_VPN -> "bgp-ls-vpn";
            default -> Integer.toString(safi);
        };
    }
}
