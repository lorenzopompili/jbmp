package it.lpworks.jbmp.protocol.bgp;

import java.util.List;
import java.util.Objects;

/**
 * The EXTENDED COMMUNITIES path attribute (type code 16): a list of 8-octet extended
 * communities.
 *
 * <p>See RFC 4360.
 *
 * @param communities the extended communities (wrapped as an immutable copy)
 */
public record ExtendedCommunities(List<ExtendedCommunity> communities) implements PathAttribute {

    /**
     * Validates and defensively copies the list.
     */
    public ExtendedCommunities {
        Objects.requireNonNull(communities, "communities");
        communities = List.copyOf(communities);
    }

    @Override
    public int typeCode() {
        return 16;
    }
}
