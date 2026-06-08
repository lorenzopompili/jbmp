package it.lpworks.jbmp.protocol.bgp;

import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * The AS_PATH path attribute (type code 2): an ordered list of segments.
 *
 * <p>See RFC 4271 §5.1.2 (and RFC 5065 for confederation segments).
 *
 * @param segments the AS_PATH segments in wire order (wrapped as an immutable copy)
 */
public record AsPath(List<AsPathSegment> segments) implements PathAttribute {

    /**
     * Validates and defensively copies the segment list.
     */
    public AsPath {
        Objects.requireNonNull(segments, "segments");
        segments = List.copyOf(segments);
    }

    @Override
    public int typeCode() {
        return 2;
    }

    /**
     * Returns the origin AS: the last ASN of the last {@link AsPathSegmentType#AS_SEQUENCE}
     * segment, ignoring confederation segments.
     *
     * @return the origin ASN, or empty when no AS_SEQUENCE segment contributes an ASN
     */
    public OptionalLong originAsn() {
        for (int i = segments.size() - 1; i >= 0; i--) {
            AsPathSegment segment = segments.get(i);
            if (segment.type() == AsPathSegmentType.AS_SEQUENCE) {
                int count = segment.asnCount();
                if (count > 0) {
                    return OptionalLong.of(segment.asnAt(count - 1));
                }
            }
        }
        return OptionalLong.empty();
    }

    /**
     * Returns the AS_PATH length used for path selection: the number of ASNs in
     * AS_SEQUENCE segments, with each AS_SET segment counting as one. Confederation
     * segments do not contribute.
     *
     * @return the computed path length
     */
    public int length() {
        int total = 0;
        for (AsPathSegment segment : segments) {
            switch (segment.type()) {
                case AS_SEQUENCE -> total += segment.asnCount();
                case AS_SET -> total += 1;
                default -> {
                    // Confederation segments are not counted toward AS_PATH length.
                }
            }
        }
        return total;
    }
}
