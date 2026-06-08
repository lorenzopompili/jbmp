package it.lpworks.jbmp.protocol.bgp;

/**
 * A BGP path attribute attached to an UPDATE message.
 *
 * <p>See RFC 4271 §4.3 / §5 for the well-known attributes, RFC 4760 for the
 * multiprotocol reach/unreach attributes, RFC 4456 for ORIGINATOR_ID and
 * CLUSTER_LIST, RFC 1997 for COMMUNITIES, RFC 4360 for extended communities and
 * RFC 8092 for large communities. This is a closed hierarchy; attributes not
 * modelled explicitly are captured by {@link UnknownAttribute}.
 */
public sealed interface PathAttribute
        permits Origin,
                AsPath,
                NextHop,
                MultiExitDisc,
                LocalPref,
                AtomicAggregate,
                Aggregator,
                Communities,
                ExtendedCommunities,
                LargeCommunities,
                OriginatorId,
                ClusterList,
                MpReachNlri,
                MpUnreachNlri,
                UnknownAttribute {

    /**
     * Returns the on-wire attribute type code.
     *
     * @return the unsigned 8-bit type code
     */
    int typeCode();
}
