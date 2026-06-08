package it.lpworks.jbmp.protocol.bmp.stat;

import java.util.Arrays;
import java.util.Objects;

/**
 * A catch-all statistic for type codes not otherwise modelled.
 *
 * <p>See RFC 7854 §4.8. The raw value bytes are preserved verbatim. {@link #value()}
 * makes a best effort to interpret them: when the payload is exactly 4 or 8 bytes it
 * is decoded as a big-endian unsigned integer (a 4-byte value is zero-extended into
 * the long); for any other length {@code 0} is returned.
 *
 * <p>The byte payload component is named {@code rawBytes} rather than {@code value}
 * because {@link StatCounter#value()} fixes the {@code value()} accessor to return a
 * {@code long}; a record component named {@code value} would otherwise generate a
 * clashing {@code byte[] value()} accessor.
 *
 * @param statType the on-wire statistic type code (unsigned 16-bit)
 * @param rawBytes the raw value bytes (defensively copied)
 */
public record UnknownStat(int statType, byte[] rawBytes) implements StatCounter {

    /**
     * Validates the fields and defensively copies the raw bytes.
     */
    public UnknownStat {
        Objects.requireNonNull(rawBytes, "rawBytes");
        rawBytes = rawBytes.clone();
    }

    /**
     * Returns a defensive copy of the raw value bytes.
     *
     * @return a fresh copy of the raw bytes
     */
    @Override
    public byte[] rawBytes() {
        return rawBytes.clone();
    }

    /**
     * Returns a best-effort numeric interpretation of the raw bytes.
     *
     * @return the big-endian unsigned value when the payload is 4 or 8 bytes long,
     *         otherwise {@code 0}
     */
    @Override
    public long value() {
        if (rawBytes.length == 4) {
            return ((long) (rawBytes[0] & 0xFF) << 24)
                    | ((long) (rawBytes[1] & 0xFF) << 16)
                    | ((long) (rawBytes[2] & 0xFF) << 8)
                    | (rawBytes[3] & 0xFF);
        }
        if (rawBytes.length == 8) {
            return ((long) (rawBytes[0] & 0xFF) << 56)
                    | ((long) (rawBytes[1] & 0xFF) << 48)
                    | ((long) (rawBytes[2] & 0xFF) << 40)
                    | ((long) (rawBytes[3] & 0xFF) << 32)
                    | ((long) (rawBytes[4] & 0xFF) << 24)
                    | ((long) (rawBytes[5] & 0xFF) << 16)
                    | ((long) (rawBytes[6] & 0xFF) << 8)
                    | (rawBytes[7] & 0xFF);
        }
        return 0L;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UnknownStat other)) {
            return false;
        }
        return statType == other.statType && Arrays.equals(rawBytes, other.rawBytes);
    }

    @Override
    public int hashCode() {
        return 31 * Integer.hashCode(statType) + Arrays.hashCode(rawBytes);
    }

    @Override
    public String toString() {
        return "UnknownStat[statType=" + statType + ", rawBytes=" + Arrays.toString(rawBytes) + ']';
    }
}
