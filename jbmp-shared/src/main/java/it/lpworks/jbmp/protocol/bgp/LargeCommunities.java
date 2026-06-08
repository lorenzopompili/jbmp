package it.lpworks.jbmp.protocol.bgp;

import java.util.List;
import java.util.Objects;

/**
 * The LARGE COMMUNITIES path attribute (type code 32): a list of large communities.
 *
 * <p>See RFC 8092.
 *
 * @param communities the large communities (wrapped as an immutable copy)
 */
public record LargeCommunities(List<LargeCommunity> communities) implements PathAttribute {

    /**
     * Validates and defensively copies the list.
     */
    public LargeCommunities {
        Objects.requireNonNull(communities, "communities");
        communities = List.copyOf(communities);
    }

    @Override
    public int typeCode() {
        return 32;
    }
}
