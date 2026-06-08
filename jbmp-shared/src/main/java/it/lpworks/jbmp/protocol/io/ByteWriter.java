package it.lpworks.jbmp.protocol.io;

import java.util.Arrays;

/**
 * A growable, big-endian byte buffer — the write-side counterpart of {@link ByteReader}.
 *
 * <p>All multi-byte integers are written in network byte order (big-endian). Unsigned
 * write methods validate their argument range. The buffer grows automatically; on the
 * high-volume encoding path a single instance may be reused across messages via
 * {@link #reset()} to avoid repeated allocation.
 *
 * <p>Back-patching helpers ({@link #reserveUint16()} / {@link #patchUint16(int, int)} and
 * the 32-bit pair) support the common pattern of writing a length prefix whose value is
 * only known after the body has been written.
 *
 * <p>This class is not thread-safe.
 */
public final class ByteWriter {

    private byte[] buffer;
    private int length;

    /** Creates a writer with a small default capacity. */
    public ByteWriter() {
        this(64);
    }

    /**
     * Creates a writer with the given initial capacity.
     *
     * @param initialCapacity the initial backing-array size (must be non-negative)
     */
    public ByteWriter(int initialCapacity) {
        if (initialCapacity < 0) {
            throw new IllegalArgumentException("Negative capacity: " + initialCapacity);
        }
        this.buffer = new byte[Math.max(initialCapacity, 16)];
        this.length = 0;
    }

    private void ensure(int extra) {
        int required = length + extra;
        if (required > buffer.length) {
            int newCapacity = buffer.length;
            while (newCapacity < required) {
                newCapacity <<= 1;
                if (newCapacity < 0) { // overflow guard
                    newCapacity = required;
                    break;
                }
            }
            buffer = Arrays.copyOf(buffer, newCapacity);
        }
    }

    /**
     * Writes a single raw byte (low 8 bits of {@code b}).
     *
     * @param b the byte value
     * @return this writer
     */
    public ByteWriter writeByte(int b) {
        ensure(1);
        buffer[length++] = (byte) b;
        return this;
    }

    /**
     * Writes an unsigned 8-bit value.
     *
     * @param value the value, in {@code [0, 255]}
     * @return this writer
     * @throws IllegalArgumentException if {@code value} is out of range
     */
    public ByteWriter writeUint8(int value) {
        if (value < 0 || value > 0xFF) {
            throw new IllegalArgumentException("uint8 out of range: " + value);
        }
        return writeByte(value);
    }

    /**
     * Writes an unsigned 16-bit value, big-endian.
     *
     * @param value the value, in {@code [0, 65535]}
     * @return this writer
     * @throws IllegalArgumentException if {@code value} is out of range
     */
    public ByteWriter writeUint16(int value) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException("uint16 out of range: " + value);
        }
        ensure(2);
        buffer[length++] = (byte) (value >>> 8);
        buffer[length++] = (byte) value;
        return this;
    }

    /**
     * Writes an unsigned 32-bit value, big-endian.
     *
     * @param value the value, in {@code [0, 4294967295]}
     * @return this writer
     * @throws IllegalArgumentException if {@code value} is out of range
     */
    public ByteWriter writeUint32(long value) {
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("uint32 out of range: " + value);
        }
        ensure(4);
        buffer[length++] = (byte) (value >>> 24);
        buffer[length++] = (byte) (value >>> 16);
        buffer[length++] = (byte) (value >>> 8);
        buffer[length++] = (byte) value;
        return this;
    }

    /**
     * Writes a raw 64-bit value, big-endian. The full unsigned range is supported; pass
     * the bits you want written (a negative {@code long} writes its two's-complement bytes).
     *
     * @param value the 64-bit value
     * @return this writer
     */
    public ByteWriter writeUint64(long value) {
        ensure(8);
        buffer[length++] = (byte) (value >>> 56);
        buffer[length++] = (byte) (value >>> 48);
        buffer[length++] = (byte) (value >>> 40);
        buffer[length++] = (byte) (value >>> 32);
        buffer[length++] = (byte) (value >>> 24);
        buffer[length++] = (byte) (value >>> 16);
        buffer[length++] = (byte) (value >>> 8);
        buffer[length++] = (byte) value;
        return this;
    }

    /**
     * Appends all bytes of the array.
     *
     * @param bytes the bytes to append
     * @return this writer
     */
    public ByteWriter writeBytes(byte[] bytes) {
        return writeBytes(bytes, 0, bytes.length);
    }

    /**
     * Appends a range of the array.
     *
     * @param bytes  the source array
     * @param offset start index
     * @param count  number of bytes
     * @return this writer
     */
    public ByteWriter writeBytes(byte[] bytes, int offset, int count) {
        if (offset < 0 || count < 0 || offset + count > bytes.length) {
            throw new IllegalArgumentException(
                    "Invalid range: offset=" + offset + ", count=" + count
                            + ", length=" + bytes.length);
        }
        ensure(count);
        System.arraycopy(bytes, offset, buffer, length, count);
        length += count;
        return this;
    }

    /**
     * Writes a {@code uint16} length prefix followed by the bytes. The array must be at
     * most 65535 bytes.
     *
     * @param bytes the length-prefixed payload
     * @return this writer
     */
    public ByteWriter writeBytesU16(byte[] bytes) {
        writeUint16(bytes.length);
        return writeBytes(bytes);
    }

    /**
     * Writes a {@code uint32} length prefix followed by the bytes (for payloads that may
     * exceed 64 KiB).
     *
     * @param bytes the length-prefixed payload
     * @return this writer
     */
    public ByteWriter writeBytesU32(byte[] bytes) {
        writeUint32(bytes.length);
        return writeBytes(bytes);
    }

    /**
     * Reserves two bytes for a {@code uint16} to be filled in later and returns their
     * index for use with {@link #patchUint16(int, int)}.
     *
     * @return the index of the reserved placeholder
     */
    public int reserveUint16() {
        int at = length;
        ensure(2);
        buffer[length++] = 0;
        buffer[length++] = 0;
        return at;
    }

    /**
     * Back-patches a {@code uint16} previously reserved with {@link #reserveUint16()}.
     *
     * @param index the placeholder index
     * @param value the value, in {@code [0, 65535]}
     * @throws IllegalArgumentException if {@code value} is out of range
     */
    public void patchUint16(int index, int value) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException("uint16 out of range: " + value);
        }
        buffer[index] = (byte) (value >>> 8);
        buffer[index + 1] = (byte) value;
    }

    /**
     * Reserves four bytes for a {@code uint32} to be filled in later.
     *
     * @return the index of the reserved placeholder
     */
    public int reserveUint32() {
        int at = length;
        ensure(4);
        length += 4;
        return at;
    }

    /**
     * Back-patches a {@code uint32} previously reserved with {@link #reserveUint32()}.
     *
     * @param index the placeholder index
     * @param value the value, in {@code [0, 4294967295]}
     * @throws IllegalArgumentException if {@code value} is out of range
     */
    public void patchUint32(int index, long value) {
        if (value < 0 || value > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("uint32 out of range: " + value);
        }
        buffer[index] = (byte) (value >>> 24);
        buffer[index + 1] = (byte) (value >>> 16);
        buffer[index + 2] = (byte) (value >>> 8);
        buffer[index + 3] = (byte) value;
    }

    /**
     * Returns the number of bytes written so far.
     *
     * @return the current length
     */
    public int length() {
        return length;
    }

    /**
     * Returns a copy of the bytes written so far.
     *
     * @return a freshly allocated array of length {@link #length()}
     */
    public byte[] toByteArray() {
        return Arrays.copyOf(buffer, length);
    }

    /**
     * Resets the length to zero, retaining the backing array for reuse. Use to recycle a
     * single writer across many messages on the encoding hot path.
     */
    public void reset() {
        length = 0;
    }
}
