package it.lpworks.jbmp.protocol.parser.bgp;

import it.lpworks.jbmp.protocol.BmpParseException;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AsPathSegmentType;
import it.lpworks.jbmp.protocol.io.ByteReader;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses AS_PATH (type code 2) and AS4_PATH (type code 17) attribute values, and
 * merges an AS4_PATH into a 2-octet AS_PATH per RFC 6793 §4.2.3.
 *
 * <p>An AS_PATH value is a sequence of segments, each encoded as a one-octet segment
 * type (RFC 4271 §4.3 / RFC 5065), a one-octet count of AS numbers, and that many AS
 * numbers. The width of each AS number is two octets in the classic encoding and four
 * octets when the speaker is 4-octet-AS capable (RFC 6793); AS4_PATH always uses
 * four-octet AS numbers. Two-octet AS numbers are widened to {@code long} on read so
 * the model carries a uniform unsigned 32-bit representation.
 *
 * <p>This is a package-private helper used by {@link PathAttributeParser}.
 */
final class AsPathParser {

    /** The reserved AS number AS_TRANS used as a 4-octet-AS placeholder (RFC 6793 §4.1). */
    static final long AS_TRANS = 23456L;

    /** Width, in octets, of a two-octet AS number. */
    private static final int ASN_WIDTH_2 = 2;

    /** Width, in octets, of a four-octet AS number. */
    private static final int ASN_WIDTH_4 = 4;

    private AsPathParser() {
        // Utility holder; not instantiable.
    }

    /**
     * Parses an AS_PATH (or AS4_PATH) attribute value into an {@link AsPath}.
     *
     * <p>The supplied reader must span exactly the attribute value. It is consumed to
     * its limit. Each segment type is resolved via
     * {@link AsPathSegmentType#fromCode(int)}; an unrecognised segment type is rejected
     * with {@link BmpParseException} so the caller can apply mode-specific handling.
     *
     * @param value      a reader spanning exactly the attribute value
     * @param asn4Octets {@code true} to read four-octet AS numbers, {@code false} for
     *                   two-octet
     * @return the parsed AS_PATH
     * @throws BmpParseException if the value is truncated or contains an unknown segment
     *                           type
     */
    static AsPath parse(ByteReader value, boolean asn4Octets) {
        int asnWidth = asn4Octets ? ASN_WIDTH_4 : ASN_WIDTH_2;
        List<AsPathSegment> segments = new ArrayList<>();
        while (value.readableBytes() > 0) {
            int segmentStart = value.position();
            int typeCode = value.readUint8();
            AsPathSegmentType type = AsPathSegmentType.fromCode(typeCode)
                    .orElseThrow(() -> new BmpParseException(
                            "Unknown AS_PATH segment type " + typeCode, segmentStart));
            int count = value.readUint8();
            long[] asns = new long[count];
            for (int i = 0; i < count; i++) {
                asns[i] = (asnWidth == ASN_WIDTH_4) ? value.readUint32() : value.readUint16();
            }
            segments.add(new AsPathSegment(type, asns));
        }
        return new AsPath(segments);
    }

    /**
     * Merges a four-octet AS4_PATH into a two-octet AS_PATH per RFC 6793 §4.2.3.
     *
     * <p>When a 4-octet-AS-incapable speaker is on the path, 4-octet AS numbers it
     * could not represent are encoded as the AS_TRANS placeholder (23456) in the
     * 2-octet AS_PATH while the true values are preserved in the AS4_PATH. To
     * reconstruct the genuine path, the trailing portion of the AS_PATH is replaced
     * with the AS4_PATH, aligned from the tail by AS_PATH "hop count" (each AS_SET or
     * confederation set counts as one, each AS in a sequence counts as one).
     *
     * <p>Per RFC 6793 §4.2.3, if the AS4_PATH has more AS-path hops than the AS_PATH,
     * the AS4_PATH is ignored and the AS_PATH is used unchanged.
     *
     * @param asPath  the 2-octet AS_PATH (the authoritative leading portion)
     * @param as4Path the 4-octet AS4_PATH (the authoritative trailing portion)
     * @return the merged AS_PATH
     */
    static AsPath merge(AsPath asPath, AsPath as4Path) {
        int asPathHops = countHops(asPath.segments());
        int as4PathHops = countHops(as4Path.segments());

        // If AS4_PATH is at least as long as AS_PATH, the AS_PATH conveys no extra
        // leading information; use the AS_PATH as-is (RFC 6793 §4.2.3).
        if (as4PathHops > asPathHops) {
            return asPath;
        }

        // Take the leading (asPathHops - as4PathHops) hops from AS_PATH, then append
        // all AS4_PATH segments, which form the authoritative tail.
        int hopsToKeep = asPathHops - as4PathHops;
        List<AsPathSegment> merged = new ArrayList<>(takeLeadingHops(asPath.segments(), hopsToKeep));
        merged.addAll(as4Path.segments());
        return new AsPath(merged);
    }

    /**
     * Counts the AS-path hops contributed by the segments, per RFC 4271 §9.1.2.2:
     * each AS in a sequence counts as one hop, and each set (ordinary or
     * confederation) counts as a single hop.
     *
     * @param segments the segments to count
     * @return the total hop count
     */
    private static int countHops(List<AsPathSegment> segments) {
        int hops = 0;
        for (AsPathSegment segment : segments) {
            hops += hopWeight(segment);
        }
        return hops;
    }

    /**
     * Returns the number of hops contributed by one segment: the AS count for sequence
     * segments, one for set segments.
     *
     * @param segment the segment
     * @return the hop weight
     */
    private static int hopWeight(AsPathSegment segment) {
        return switch (segment.type()) {
            case AS_SEQUENCE, AS_CONFED_SEQUENCE -> segment.asns().length;
            case AS_SET, AS_CONFED_SET -> 1;
        };
    }

    /**
     * Returns the leading segments of {@code segments} that together account for the
     * first {@code hopsToKeep} hops, splitting a sequence segment if necessary.
     *
     * @param segments   the source segments
     * @param hopsToKeep the number of leading hops to retain
     * @return a fresh list of segments covering exactly the leading hops
     */
    private static List<AsPathSegment> takeLeadingHops(List<AsPathSegment> segments, int hopsToKeep) {
        List<AsPathSegment> kept = new ArrayList<>();
        int remaining = hopsToKeep;
        for (AsPathSegment segment : segments) {
            if (remaining <= 0) {
                break;
            }
            int weight = hopWeight(segment);
            if (weight <= remaining) {
                kept.add(segment);
                remaining -= weight;
            } else {
                // Must be a sequence segment partially consumed: keep its first
                // `remaining` AS numbers.
                long[] all = segment.asns();
                long[] head = new long[remaining];
                System.arraycopy(all, 0, head, 0, remaining);
                kept.add(new AsPathSegment(segment.type(), head));
                remaining = 0;
            }
        }
        return kept;
    }
}
