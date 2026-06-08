package it.lpworks.jbmp.protocol.bgp;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A decoded BGP UPDATE message.
 *
 * <p>See RFC 4271 §4.3. An UPDATE carries withdrawn routes, path attributes and
 * newly advertised NLRI. Multiprotocol reachability/withdrawal for non-IPv4-unicast
 * families is carried inside the {@link MpReachNlri} / {@link MpUnreachNlri}
 * attributes rather than in the {@code withdrawnRoutes}/{@code nlri} lists.
 *
 * @param withdrawnRoutes the IPv4-unicast routes being withdrawn (immutable copy)
 * @param pathAttributes  the path attributes (immutable copy)
 * @param nlri            the IPv4-unicast routes being advertised (immutable copy)
 */
public record BgpUpdate(
        List<IpPrefix> withdrawnRoutes,
        List<PathAttribute> pathAttributes,
        List<IpPrefix> nlri) {

    /**
     * Validates and defensively copies the lists.
     */
    public BgpUpdate {
        Objects.requireNonNull(withdrawnRoutes, "withdrawnRoutes");
        Objects.requireNonNull(pathAttributes, "pathAttributes");
        Objects.requireNonNull(nlri, "nlri");
        withdrawnRoutes = List.copyOf(withdrawnRoutes);
        pathAttributes = List.copyOf(pathAttributes);
        nlri = List.copyOf(nlri);
    }

    /**
     * Returns the first path attribute of the requested concrete type, if present.
     *
     * @param type the path-attribute implementation class to look up
     * @param <T>  the path-attribute type
     * @return the first matching attribute, or empty if none is present
     */
    public <T extends PathAttribute> Optional<T> attribute(Class<T> type) {
        Objects.requireNonNull(type, "type");
        for (PathAttribute attribute : pathAttributes) {
            if (type.isInstance(attribute)) {
                return Optional.of(type.cast(attribute));
            }
        }
        return Optional.empty();
    }

    /**
     * Reports whether this UPDATE is an End-of-RIB marker (RFC 4724 §2).
     *
     * <p>This is true when the message carries no withdrawn routes, no advertised
     * NLRI and no path attributes (the IPv4-unicast End-of-RIB), or when its only
     * path attribute is an {@link MpUnreachNlri} whose withdrawn NLRI is empty (the
     * multiprotocol End-of-RIB), with no IPv4-unicast routes present.
     *
     * @return {@code true} if this message is an End-of-RIB marker
     */
    public boolean isEndOfRib() {
        if (!withdrawnRoutes.isEmpty() || !nlri.isEmpty()) {
            return false;
        }
        if (pathAttributes.isEmpty()) {
            return true;
        }
        if (pathAttributes.size() == 1
                && pathAttributes.get(0) instanceof MpUnreachNlri unreach) {
            return unreach.withdrawnNlri().length == 0;
        }
        return false;
    }
}
