package it.lpworks.jbmp.protocol.bgp;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Objects;

/**
 * An IPv4 or IPv6 unicast prefix, expressed as an address plus a prefix length.
 *
 * <p>See RFC 4271 §4.3. The prefix length is validated against the address family:
 * {@code [0, 32]} for IPv4, {@code [0, 128]} for IPv6.
 *
 * @param address      the (network) address
 * @param prefixLength the prefix length in bits
 */
public record IpPrefix(InetAddress address, int prefixLength) implements Nlri {

    /**
     * Validates the address family and prefix length.
     */
    public IpPrefix {
        Objects.requireNonNull(address, "address");
        int max = maxPrefixLength(address);
        if (prefixLength < 0 || prefixLength > max) {
            throw new IllegalArgumentException(
                    "prefixLength must be in [0, " + max + "] for "
                            + address.getClass().getSimpleName() + " but was " + prefixLength);
        }
    }

    private static int maxPrefixLength(InetAddress address) {
        if (address instanceof Inet4Address) {
            return 32;
        }
        if (address instanceof Inet6Address) {
            return 128;
        }
        throw new IllegalArgumentException(
                "Unsupported address type: " + address.getClass().getName());
    }

    /**
     * Returns the AFI for this prefix.
     *
     * @return {@link AddressFamily#AFI_IPV4} or {@link AddressFamily#AFI_IPV6}
     */
    @Override
    public int afi() {
        return (address instanceof Inet4Address) ? AddressFamily.AFI_IPV4 : AddressFamily.AFI_IPV6;
    }

    /**
     * Returns the SAFI for this prefix.
     *
     * @return {@link AddressFamily#SAFI_UNICAST}
     */
    @Override
    public int safi() {
        return AddressFamily.SAFI_UNICAST;
    }

    /**
     * Renders the prefix in CIDR notation.
     *
     * @return a string of the form {@code address/prefixLength}
     */
    public String asCidr() {
        return address.getHostAddress() + "/" + prefixLength;
    }
}
