package it.lpworks.jbmp.identity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.UUID;

/**
 * Derives stable, content-addressed {@link UUID}s for routers and BGP peers.
 *
 * <p>Identities are computed as name-based UUIDs (RFC 4122, Section 4.3): the stable
 * inputs are concatenated, hashed with SHA-256, and the first 16 octets of the digest are
 * trimmed to a UUID with the version field set to {@code 5} and the variant set to the
 * RFC 4122 form ({@code 10xx}). RFC 4122 specifies SHA-1 for version 5; this factory uses
 * SHA-256 truncated to 16 bytes, which yields the same byte layout and the same
 * version/variant bits while avoiding SHA-1. The construction is purely deterministic:
 * <strong>identical inputs always produce an equal UUID</strong>, and distinct inputs
 * produce different UUIDs with overwhelming probability, so collectors can independently
 * compute the same identity for the same router or peer without coordination.
 *
 * <p>This class is not instantiable.
 */
public final class UuidFactory {

    private static final long ASN_MAX_UINT32 = 0xFFFFFFFFL;

    private UuidFactory() {
        throw new AssertionError("No instances");
    }

    /**
     * Derives the deterministic identity of a router from its IP address.
     *
     * <p>The digest input is exactly the supplied address bytes. The same address always
     * yields an equal UUID.
     *
     * @param routerIp the router's IP address bytes (typically 4 or 16 octets); not copied
     *                 beyond hashing and never mutated
     * @return the router's name-based (version 5) UUID
     * @throws NullPointerException if {@code routerIp} is {@code null}
     */
    public static UUID router(byte[] routerIp) {
        Objects.requireNonNull(routerIp, "routerIp");
        MessageDigest digest = sha256();
        digest.update(routerIp);
        return fromDigest(digest.digest());
    }

    /**
     * Derives the deterministic identity of a BGP peer.
     *
     * <p>The digest input is, in order: the 16 bytes of {@code routerId} (most-significant
     * 64 bits then least-significant 64 bits, big-endian), the peer IP bytes, the peer ASN
     * as 8 big-endian bytes, and the route distinguisher encoded as UTF-8. The same
     * combination of inputs always yields an equal UUID.
     *
     * @param routerId          the owning router's identity, as produced by
     *                          {@link #router(byte[])} (never {@code null})
     * @param peerIp            the peer's IP address bytes (typically 4 or 16 octets);
     *                          never {@code null}
     * @param peerAsn           the peer AS number; an unsigned 32-bit value (RFC 6793),
     *                          hashed as 8 big-endian bytes
     * @param routeDistinguisher the peer/VRF route distinguisher (RFC 4364); never
     *                          {@code null} (use {@code ""} when none applies)
     * @return the peer's name-based (version 5) UUID
     * @throws NullPointerException     if any reference argument is {@code null}
     * @throws IllegalArgumentException if {@code peerAsn} is outside {@code [0, 2^32-1]}
     */
    public static UUID peer(UUID routerId, byte[] peerIp, long peerAsn, String routeDistinguisher) {
        Objects.requireNonNull(routerId, "routerId");
        Objects.requireNonNull(peerIp, "peerIp");
        Objects.requireNonNull(routeDistinguisher, "routeDistinguisher");
        if (peerAsn < 0 || peerAsn > ASN_MAX_UINT32) {
            throw new IllegalArgumentException(
                    "peerAsn must be a uint32 in [0, " + ASN_MAX_UINT32 + "] but was " + peerAsn);
        }

        MessageDigest digest = sha256();
        digest.update(toBytes(routerId));
        digest.update(peerIp);
        digest.update(asnToBytes(peerAsn));
        digest.update(routeDistinguisher.getBytes(StandardCharsets.UTF_8));
        return fromDigest(digest.digest());
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated for every conformant Java platform.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static byte[] toBytes(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        byte[] out = new byte[16];
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (msb >>> (56 - 8 * i));
            out[8 + i] = (byte) (lsb >>> (56 - 8 * i));
        }
        return out;
    }

    private static byte[] asnToBytes(long asn) {
        return new byte[]{
                (byte) (asn >>> 56),
                (byte) (asn >>> 48),
                (byte) (asn >>> 40),
                (byte) (asn >>> 32),
                (byte) (asn >>> 24),
                (byte) (asn >>> 16),
                (byte) (asn >>> 8),
                (byte) asn
        };
    }

    /**
     * Builds a name-based UUID from the first 16 bytes of a digest, applying the RFC 4122
     * version (5) and variant ({@code 10xx}) bits.
     */
    private static UUID fromDigest(byte[] digest) {
        byte[] b = new byte[16];
        System.arraycopy(digest, 0, b, 0, 16);
        b[6] = (byte) ((b[6] & 0x0F) | 0x50); // version 5
        b[8] = (byte) ((b[8] & 0x3F) | 0x80); // variant 10xx
        long msb = 0;
        long lsb = 0;
        for (int i = 0; i < 8; i++) {
            msb = (msb << 8) | (b[i] & 0xFF);
        }
        for (int i = 8; i < 16; i++) {
            lsb = (lsb << 8) | (b[i] & 0xFF);
        }
        return new UUID(msb, lsb);
    }
}
