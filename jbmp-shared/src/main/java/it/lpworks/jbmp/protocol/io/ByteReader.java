package it.lpworks.jbmp.protocol.io;

import it.lpworks.jbmp.protocol.BmpParseException;

import java.util.Arrays;

/**
 * A forward-only, big-endian reader over a region of a {@code byte[]}.
 *
 * <p>The reader tracks an absolute {@code offset} (the start of its window inside
 * the backing array), a {@code limit} (one past the last readable byte) and a
 * current {@code position}. It is performance sensitive: no allocation is
 * performed except by operations whose contract explicitly requires a copy
 * ({@link #readBytes(int)}) or a fresh view ({@link #slice(int)}).
 *
 * <p>All multi-byte integers are interpreted in network byte order (big-endian),
 * as mandated for BMP (RFC 7854) and BGP (RFC 4271).
 *
 * <p>This class is not thread-safe.
 */
public final class ByteReader {

    private final byte[] data;
    private final int offset;
    private final int limit;
    private int position;

    /**
     * Creates a reader spanning the entire array.
     *
     * @param data the backing array (not copied; the caller must not mutate it
     *             while the reader is in use)
     */
    public ByteReader(byte[] data) {
        this(data, 0, data.length);
    }

    /**
     * Creates a reader over a sub-range of the array.
     *
     * @param data   the backing array (not copied)
     * @param offset absolute start index of the window, in {@code [0, data.length]}
     * @param length number of bytes in the window; {@code offset + length} must
     *               not exceed {@code data.length}
     * @throws IllegalArgumentException if the range is out of bounds
     */
    public ByteReader(byte[] data, int offset, int length) {
        if (offset < 0 || length < 0 || offset + length > data.length) {
            throw new IllegalArgumentException(
                    "Invalid window: offset=" + offset + ", length=" + length
                            + ", arrayLength=" + data.length);
        }
        this.data = data;
        this.offset = offset;
        this.limit = offset + length;
        this.position = offset;
    }

    /**
     * Returns the number of bytes remaining between the current position and the limit.
     *
     * @return remaining readable bytes (never negative)
     */
    public int readableBytes() {
        return limit - position;
    }

    /**
     * Reports whether at least {@code n} bytes remain to be read.
     *
     * @param n the byte count to test for
     * @return {@code true} if {@code n} or more bytes remain
     */
    public boolean isReadable(int n) {
        return readableBytes() >= n;
    }

    /**
     * Ensures at least {@code n} bytes remain, throwing otherwise.
     *
     * @param n the required byte count
     * @throws BmpParseException if fewer than {@code n} bytes remain; the message
     *                           reports the needed and available counts and the
     *                           absolute current offset
     */
    public void require(int n) {
        if (readableBytes() < n) {
            throw new BmpParseException(
                    "Buffer underflow: need " + n + " byte(s) but " + readableBytes()
                            + " available at offset " + position,
                    position);
        }
    }

    /**
     * Reads one byte as an unsigned 8-bit value.
     *
     * @return the value in {@code [0, 255]}
     * @throws BmpParseException if no byte remains
     */
    public int readUint8() {
        require(1);
        return data[position++] & 0xFF;
    }

    /**
     * Reads two bytes as an unsigned 16-bit value.
     *
     * @return the value in {@code [0, 65535]}
     * @throws BmpParseException if fewer than two bytes remain
     */
    public int readUint16() {
        require(2);
        int value = ((data[position] & 0xFF) << 8) | (data[position + 1] & 0xFF);
        position += 2;
        return value;
    }

    /**
     * Reads four bytes as an unsigned 32-bit value.
     *
     * @return the value in {@code [0, 4294967295]}
     * @throws BmpParseException if fewer than four bytes remain
     */
    public long readUint32() {
        require(4);
        long value = ((long) (data[position] & 0xFF) << 24)
                | ((long) (data[position + 1] & 0xFF) << 16)
                | ((long) (data[position + 2] & 0xFF) << 8)
                | (data[position + 3] & 0xFF);
        position += 4;
        return value;
    }

    /**
     * Reads eight bytes as a raw 64-bit value.
     *
     * <p>The full 64-bit range cannot fit in a signed {@code long}; values with the
     * most significant bit set are returned as negative {@code long}s. Callers that
     * require unsigned semantics should use {@link Long#toUnsignedString(long)} or
     * {@link Long#compareUnsigned(long, long)}.
     *
     * @return the raw 64-bit value, possibly negative when interpreted as signed
     * @throws BmpParseException if fewer than eight bytes remain
     */
    public long readUint64() {
        require(8);
        long value = ((long) (data[position] & 0xFF) << 56)
                | ((long) (data[position + 1] & 0xFF) << 48)
                | ((long) (data[position + 2] & 0xFF) << 40)
                | ((long) (data[position + 3] & 0xFF) << 32)
                | ((long) (data[position + 4] & 0xFF) << 24)
                | ((long) (data[position + 5] & 0xFF) << 16)
                | ((long) (data[position + 6] & 0xFF) << 8)
                | (data[position + 7] & 0xFF);
        position += 8;
        return value;
    }

    /**
     * Reads one raw signed byte.
     *
     * @return the byte in {@code [-128, 127]}
     * @throws BmpParseException if no byte remains
     */
    public byte readByte() {
        require(1);
        return data[position++];
    }

    /**
     * Reads {@code n} bytes into a fresh array.
     *
     * @param n number of bytes to read (must be non-negative)
     * @return a newly allocated array of length {@code n}
     * @throws BmpParseException        if fewer than {@code n} bytes remain
     * @throws IllegalArgumentException if {@code n} is negative
     */
    public byte[] readBytes(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("Negative length: " + n);
        }
        require(n);
        byte[] out = Arrays.copyOfRange(data, position, position + n);
        position += n;
        return out;
    }

    /**
     * Advances the position by {@code n} bytes without reading them.
     *
     * @param n number of bytes to skip (must be non-negative)
     * @throws BmpParseException        if fewer than {@code n} bytes remain
     * @throws IllegalArgumentException if {@code n} is negative
     */
    public void skip(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("Negative length: " + n);
        }
        require(n);
        position += n;
    }

    /**
     * Returns the current absolute read position within the backing array.
     *
     * @return the current position
     */
    public int position() {
        return position;
    }

    /**
     * Sets the current absolute read position.
     *
     * @param newPosition the new position, in {@code [offset, limit]}
     * @throws IllegalArgumentException if the position is outside the reader window
     */
    public void position(int newPosition) {
        if (newPosition < offset || newPosition > limit) {
            throw new IllegalArgumentException(
                    "Position " + newPosition + " out of window [" + offset + ", " + limit + "]");
        }
        this.position = newPosition;
    }

    /**
     * Returns the absolute start index of this reader's window.
     *
     * @return the window start offset
     */
    public int offset() {
        return offset;
    }

    /**
     * Returns the absolute end index (exclusive) of this reader's window.
     *
     * @return the window limit
     */
    public int limit() {
        return limit;
    }

    /**
     * Returns a new reader over the next {@code length} bytes and advances this
     * reader past them.
     *
     * <p>The returned reader shares this reader's backing array (no copy is made);
     * its window is {@code [position, position + length)}.
     *
     * @param length the size of the slice (must be non-negative)
     * @return a new reader positioned at the start of the slice
     * @throws BmpParseException        if fewer than {@code length} bytes remain
     * @throws IllegalArgumentException if {@code length} is negative
     */
    public ByteReader slice(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("Negative length: " + length);
        }
        require(length);
        ByteReader child = new ByteReader(data, position, length);
        position += length;
        return child;
    }
}
