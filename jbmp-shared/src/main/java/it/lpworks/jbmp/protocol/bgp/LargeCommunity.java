package it.lpworks.jbmp.protocol.bgp;

/**
 * A BGP large community: three 32-bit fields.
 *
 * <p>See RFC 8092. The fields are a Global Administrator followed by two Local Data
 * fields, each an unsigned 32-bit value conveyed in a {@code long}.
 *
 * @param globalAdministrator the global administrator field, in {@code [0, 4294967295]}
 * @param localData1          the first local data field, in {@code [0, 4294967295]}
 * @param localData2          the second local data field, in {@code [0, 4294967295]}
 */
public record LargeCommunity(long globalAdministrator, long localData1, long localData2) {

    /** Largest representable unsigned 32-bit value. */
    private static final long MAX_UINT32 = 0xFFFFFFFFL;

    /**
     * Validates that all three fields are unsigned 32-bit values.
     */
    public LargeCommunity {
        check("globalAdministrator", globalAdministrator);
        check("localData1", localData1);
        check("localData2", localData2);
    }

    private static void check(String name, long v) {
        if (v < 0 || v > MAX_UINT32) {
            throw new IllegalArgumentException(
                    name + " must be a uint32 in [0, " + MAX_UINT32 + "] but was " + v);
        }
    }
}
