package it.lpworks.jbmp.protocol.bmp;

import java.util.Objects;

/**
 * The fixed common header that prefixes every BMP message.
 *
 * <p>On the wire the header is a 1-byte version, a 4-byte total message length and
 * a 1-byte message type. See RFC 7854 §4.1.
 *
 * @param version       protocol version; must be {@code 3}
 * @param messageLength total length of the message in bytes including this header,
 *                      an unsigned 32-bit value in {@code [6, 4294967295]}
 * @param type          the message type
 */
public record BmpCommonHeader(int version, long messageLength, BmpMessageType type) {

    /** Smallest legal message length: the common header itself is 6 bytes. */
    private static final long MIN_LENGTH = 6L;

    /** Largest representable unsigned 32-bit length. */
    private static final long MAX_LENGTH = 0xFFFFFFFFL;

    /**
     * Validates the header fields.
     */
    public BmpCommonHeader {
        if (version != 3) {
            throw new IllegalArgumentException("BMP version must be 3 but was " + version);
        }
        if (messageLength < MIN_LENGTH || messageLength > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "messageLength must be in [" + MIN_LENGTH + ", " + MAX_LENGTH
                            + "] but was " + messageLength);
        }
        Objects.requireNonNull(type, "type");
    }
}
