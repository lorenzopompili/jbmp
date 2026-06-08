package it.lpworks.jbmp.protocol.parser.bgp;

import it.lpworks.jbmp.protocol.BmpParseException;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.io.ByteReader;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Decodes the length-prefixed IPv4 prefix encoding shared by the BGP UPDATE
 * Withdrawn Routes and NLRI fields.
 *
 * <p>See RFC 4271 §4.3. Each prefix is encoded as a one-octet prefix length (in
 * bits) followed by {@code ceil(bits / 8)} value octets; the value octets are the
 * most-significant bytes of the address and are right-padded with zero bytes to a
 * full four-octet IPv4 address.
 *
 * <p>This is a package-private helper used by {@link BgpUpdateParser}.
 */
final class PrefixReader {

    /** Maximum valid IPv4 prefix length, in bits. */
    private static final int MAX_IPV4_PREFIX_BITS = 32;

    /** Number of octets in an IPv4 address. */
    private static final int IPV4_ADDRESS_BYTES = 4;

    private PrefixReader() {
        // Utility holder; not instantiable.
    }

    /**
     * Reads every IPv4 prefix from the supplied reader, consuming it to its limit.
     *
     * <p>The reader is expected to be a {@link ByteReader#slice(int) slice} spanning
     * exactly the Withdrawn Routes or NLRI field, so that exhausting it yields all
     * prefixes of that field.
     *
     * <p>In {@link it.lpworks.jbmp.protocol.parser.ParseMode#STRICT} a malformed or
     * truncated prefix raises {@link BmpParseException}. In
     * {@link it.lpworks.jbmp.protocol.parser.ParseMode#LENIENT} parsing of the field
     * stops at the first malformed prefix, returning the prefixes decoded so far
     * (RFC 4271 §6.3 resilience).
     *
     * @param reader a reader positioned at the start of a prefix field; it is read to
     *               its limit
     * @param strict whether to fail hard on malformed input
     * @return the decoded prefixes in wire order (never {@code null})
     * @throws BmpParseException in strict mode when a prefix is malformed or truncated
     */
    static List<IpPrefix> readPrefixes(ByteReader reader, boolean strict) {
        List<IpPrefix> prefixes = new ArrayList<>();
        while (reader.readableBytes() > 0) {
            int markBeforePrefix = reader.position();
            try {
                prefixes.add(readPrefix(reader));
            } catch (BmpParseException | IllegalArgumentException e) {
                if (strict) {
                    if (e instanceof BmpParseException bpe) {
                        throw bpe;
                    }
                    throw new BmpParseException(
                            "Malformed IPv4 prefix: " + e.getMessage(), markBeforePrefix);
                }
                // Lenient: stop this field, keep what was decoded.
                break;
            }
        }
        return prefixes;
    }

    /**
     * Reads a single length-prefixed IPv4 prefix.
     *
     * @param reader a reader positioned at the prefix-length octet
     * @return the decoded prefix
     * @throws BmpParseException        if the prefix is truncated
     * @throws IllegalArgumentException if the prefix length exceeds 32 bits
     */
    private static IpPrefix readPrefix(ByteReader reader) {
        int prefixBits = reader.readUint8();
        if (prefixBits > MAX_IPV4_PREFIX_BITS) {
            throw new BmpParseException(
                    "IPv4 prefix length " + prefixBits + " exceeds " + MAX_IPV4_PREFIX_BITS + " bits",
                    reader.position());
        }
        int valueBytes = (prefixBits + 7) / 8;
        byte[] significant = reader.readBytes(valueBytes);
        byte[] address = new byte[IPV4_ADDRESS_BYTES];
        System.arraycopy(significant, 0, address, 0, valueBytes);
        return new IpPrefix(toInet4(address, reader.position()), prefixBits);
    }

    /**
     * Builds an {@link Inet4Address} from exactly four octets.
     *
     * @param fourBytes the address octets (length 4)
     * @param offset    the absolute offset for diagnostics
     * @return the IPv4 address
     * @throws BmpParseException if the platform rejects the address bytes
     */
    static Inet4Address toInet4(byte[] fourBytes, int offset) {
        try {
            return (Inet4Address) InetAddress.getByAddress(fourBytes);
        } catch (UnknownHostException e) {
            // Only thrown for an illegal length, which cannot happen with 4 bytes.
            throw new BmpParseException("Invalid IPv4 address bytes", offset);
        }
    }
}
