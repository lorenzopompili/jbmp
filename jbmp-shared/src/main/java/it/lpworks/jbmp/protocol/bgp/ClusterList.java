package it.lpworks.jbmp.protocol.bgp;

import java.net.Inet4Address;
import java.util.List;
import java.util.Objects;

/**
 * The CLUSTER_LIST path attribute (type code 10): the sequence of CLUSTER_IDs a
 * route has traversed inside a route-reflection topology.
 *
 * <p>See RFC 4456. Each CLUSTER_ID is a 4-octet value modelled as an IPv4 address.
 *
 * @param clusterIds the cluster identifiers in order (wrapped as an immutable copy)
 */
public record ClusterList(List<Inet4Address> clusterIds) implements PathAttribute {

    /**
     * Validates and defensively copies the list.
     */
    public ClusterList {
        Objects.requireNonNull(clusterIds, "clusterIds");
        clusterIds = List.copyOf(clusterIds);
    }

    @Override
    public int typeCode() {
        return 10;
    }
}
