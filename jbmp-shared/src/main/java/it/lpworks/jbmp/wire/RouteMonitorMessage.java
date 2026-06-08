package it.lpworks.jbmp.wire;

import it.lpworks.jbmp.protocol.bgp.LargeCommunity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

/**
 * An enriched, fully-decoded single-prefix route event derived from a BMP Route
 * Monitoring message (RFC 7854, Section 4.6) and the BGP UPDATE (RFC 4271 / RFC 4760) it
 * carries.
 *
 * <p>Each BGP UPDATE can advertise or withdraw many prefixes; the enrichment stage
 * explodes those into one {@code RouteMonitorMessage} per prefix so that downstream
 * consumers handle a uniform, flat shape. The BGP path attributes are decoded into typed
 * fields; less-common or address-family-specific NLRI payloads are kept as opaque blobs
 * for forward compatibility.
 *
 * <h2>Null and absence policy</h2>
 * <p>This record is immutable. Every {@code byte[]}, {@code long[]} and {@code int[]} is
 * defensively copied on construction and on every accessor. An <em>absent</em> binary
 * field is represented by an empty array, never {@code null}; an absent scalar is
 * represented by an empty {@link OptionalLong}/{@link Optional}. Lists are copied with
 * {@link List#copyOf(java.util.Collection)} and are therefore unmodifiable and
 * null-element free.
 *
 * @param header           the provenance header (never {@code null})
 * @param action           announce or withdraw (never {@code null})
 * @param prePolicy        {@code true} if observed pre-policy (Adj-RIB-In before inbound
 *                         policy), per the BMP Per-Peer Header L-flag (RFC 7854 §4.2)
 * @param locRib           {@code true} if sourced from the Loc-RIB (RFC 9069)
 * @param ipv4             {@code true} for IPv4 reachability, {@code false} for IPv6
 * @param endOfRib         {@code true} if this marks an End-of-RIB (RFC 4724) for the AFI/SAFI
 * @param addPath          {@code true} if ADD-PATH (RFC 7911) was in effect for this NLRI
 * @param prefix           the network prefix bytes (4 for IPv4, 16 for IPv6); empty if absent
 * @param prefixLength     the prefix length in bits
 * @param pathId           the ADD-PATH Path Identifier (RFC 7911), if {@code addPath}
 * @param originAsn        the originating AS (last ASN of the AS_PATH), if determinable
 * @param asPath           the flattened AS_PATH as an ordered ASN array (RFC 4271 §5.1.2)
 * @param asPathSegments   the structured AS_PATH segments (never {@code null})
 * @param nextHop          the BGP NEXT_HOP (RFC 4271 §5.1.3) or MP next hop (RFC 4760); empty if absent
 * @param med              the MULTI_EXIT_DISC (RFC 4271 §5.1.4), if present
 * @param localPref        the LOCAL_PREF (RFC 4271 §5.1.5), if present
 * @param origin           the ORIGIN (RFC 4271 §5.1.1): {@code 0}=IGP, {@code 1}=EGP,
 *                         {@code 2}=INCOMPLETE, {@code -1}=absent
 * @param atomicAggregate  the ATOMIC_AGGREGATE flag (RFC 4271 §5.1.6)
 * @param aggregatorAsn    the AGGREGATOR ASN (RFC 4271 §5.1.7 / RFC 6793), if present
 * @param aggregatorAddress the AGGREGATOR BGP identifier address; empty if absent
 * @param communities      the COMMUNITIES (RFC 1997), each a 32-bit value in an {@code int}
 * @param largeCommunities the LARGE_COMMUNITIES (RFC 8092) (never {@code null})
 * @param extendedCommunities the EXTENDED_COMMUNITIES (RFC 4360), each an 8-byte blob (never {@code null})
 * @param originatorId     the ORIGINATOR_ID (RFC 4456), if present
 * @param clusterList      the CLUSTER_LIST (RFC 4456) (never {@code null})
 * @param peerRd           the Route Distinguisher of the peer/VRF (RFC 4364), if any; empty string if absent
 * @param vprnId           an implementation-assigned VPRN/VRF identifier
 * @param routeTargets     the route-target extended-community strings (RFC 4364) (never {@code null})
 * @param mplsLabels       the MPLS label stack (RFC 3107 / RFC 8277), each a 20-bit label in a {@code long}
 * @param evpn             opaque EVPN NLRI bytes (RFC 7432); empty if absent
 * @param flowSpec         opaque Flow Specification NLRI bytes (RFC 8955); empty if absent
 * @param srPolicy         opaque SR Policy NLRI bytes; empty if absent
 * @param linkState        opaque BGP-LS NLRI bytes (RFC 7752); empty if absent
 * @param rawNlri          the raw, undecoded NLRI bytes; empty if absent
 */
public record RouteMonitorMessage(
        MessageHeader header,
        RouteAction action,
        boolean prePolicy,
        boolean locRib,
        boolean ipv4,
        boolean endOfRib,
        boolean addPath,
        byte[] prefix,
        int prefixLength,
        OptionalLong pathId,
        OptionalLong originAsn,
        long[] asPath,
        List<AsPathSegmentInfo> asPathSegments,
        byte[] nextHop,
        OptionalLong med,
        OptionalLong localPref,
        int origin,
        boolean atomicAggregate,
        OptionalLong aggregatorAsn,
        byte[] aggregatorAddress,
        int[] communities,
        List<LargeCommunity> largeCommunities,
        List<byte[]> extendedCommunities,
        Optional<UUID> originatorId,
        List<UUID> clusterList,
        String peerRd,
        long vprnId,
        List<String> routeTargets,
        long[] mplsLabels,
        byte[] evpn,
        byte[] flowSpec,
        byte[] srPolicy,
        byte[] linkState,
        byte[] rawNlri) {

    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final long[] EMPTY_LONGS = new long[0];
    private static final int[] EMPTY_INTS = new int[0];

    /**
     * Canonicalises every field: substitutes empty arrays/strings/optionals for
     * {@code null}, defensively copies all mutable arrays, and makes all lists immutable
     * via {@link List#copyOf(java.util.Collection)} (extended communities are deep-copied
     * because their elements are mutable {@code byte[]}).
     *
     * @throws NullPointerException if {@code header} or {@code action} is {@code null}
     */
    public RouteMonitorMessage {
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(action, "action");

        prefix = copyOrEmpty(prefix);
        nextHop = copyOrEmpty(nextHop);
        aggregatorAddress = copyOrEmpty(aggregatorAddress);
        evpn = copyOrEmpty(evpn);
        flowSpec = copyOrEmpty(flowSpec);
        srPolicy = copyOrEmpty(srPolicy);
        linkState = copyOrEmpty(linkState);
        rawNlri = copyOrEmpty(rawNlri);

        asPath = (asPath == null) ? EMPTY_LONGS : asPath.clone();
        mplsLabels = (mplsLabels == null) ? EMPTY_LONGS : mplsLabels.clone();
        communities = (communities == null) ? EMPTY_INTS : communities.clone();

        pathId = (pathId == null) ? OptionalLong.empty() : pathId;
        originAsn = (originAsn == null) ? OptionalLong.empty() : originAsn;
        med = (med == null) ? OptionalLong.empty() : med;
        localPref = (localPref == null) ? OptionalLong.empty() : localPref;
        aggregatorAsn = (aggregatorAsn == null) ? OptionalLong.empty() : aggregatorAsn;
        originatorId = (originatorId == null) ? Optional.empty() : originatorId;

        asPathSegments = (asPathSegments == null) ? List.of() : List.copyOf(asPathSegments);
        largeCommunities = (largeCommunities == null) ? List.of() : List.copyOf(largeCommunities);
        clusterList = (clusterList == null) ? List.of() : List.copyOf(clusterList);
        routeTargets = (routeTargets == null) ? List.of() : List.copyOf(routeTargets);

        extendedCommunities = copyExtended(extendedCommunities);

        peerRd = (peerRd == null) ? "" : peerRd;
    }

    private static byte[] copyOrEmpty(byte[] b) {
        return (b == null || b.length == 0) ? EMPTY_BYTES : b.clone();
    }

    private static List<byte[]> copyExtended(List<byte[]> list) {
        if (list == null || list.isEmpty()) {
            return List.of();
        }
        List<byte[]> copy = new ArrayList<>(list.size());
        for (byte[] ec : list) {
            copy.add(ec == null ? EMPTY_BYTES : ec.clone());
        }
        return List.copyOf(copy);
    }

    /** @return a defensive copy of the prefix bytes */
    @Override
    public byte[] prefix() {
        return prefix.clone();
    }

    /** @return a defensive copy of the AS_PATH ASN array */
    @Override
    public long[] asPath() {
        return asPath.clone();
    }

    /** @return a defensive copy of the next-hop bytes */
    @Override
    public byte[] nextHop() {
        return nextHop.clone();
    }

    /** @return a defensive copy of the aggregator address bytes */
    @Override
    public byte[] aggregatorAddress() {
        return aggregatorAddress.clone();
    }

    /** @return a defensive copy of the COMMUNITIES array */
    @Override
    public int[] communities() {
        return communities.clone();
    }

    /** @return a deep defensive copy of the extended-community blobs */
    @Override
    public List<byte[]> extendedCommunities() {
        List<byte[]> copy = new ArrayList<>(extendedCommunities.size());
        for (byte[] ec : extendedCommunities) {
            copy.add(ec.clone());
        }
        return copy;
    }

    /** @return a defensive copy of the MPLS label stack */
    @Override
    public long[] mplsLabels() {
        return mplsLabels.clone();
    }

    /** @return a defensive copy of the EVPN NLRI bytes */
    @Override
    public byte[] evpn() {
        return evpn.clone();
    }

    /** @return a defensive copy of the Flow Specification NLRI bytes */
    @Override
    public byte[] flowSpec() {
        return flowSpec.clone();
    }

    /** @return a defensive copy of the SR Policy NLRI bytes */
    @Override
    public byte[] srPolicy() {
        return srPolicy.clone();
    }

    /** @return a defensive copy of the BGP-LS NLRI bytes */
    @Override
    public byte[] linkState() {
        return linkState.clone();
    }

    /** @return a defensive copy of the raw NLRI bytes */
    @Override
    public byte[] rawNlri() {
        return rawNlri.clone();
    }

    /**
     * Value equality with element-wise comparison of every array (including the elements
     * of the extended-community list) and standard equality for all other components.
     *
     * @param o the object to compare with
     * @return {@code true} if {@code o} is an equal {@code RouteMonitorMessage}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RouteMonitorMessage other)) {
            return false;
        }
        return prePolicy == other.prePolicy
                && locRib == other.locRib
                && ipv4 == other.ipv4
                && endOfRib == other.endOfRib
                && addPath == other.addPath
                && prefixLength == other.prefixLength
                && origin == other.origin
                && atomicAggregate == other.atomicAggregate
                && vprnId == other.vprnId
                && header.equals(other.header)
                && action == other.action
                && Arrays.equals(prefix, other.prefix)
                && pathId.equals(other.pathId)
                && originAsn.equals(other.originAsn)
                && Arrays.equals(asPath, other.asPath)
                && asPathSegments.equals(other.asPathSegments)
                && Arrays.equals(nextHop, other.nextHop)
                && med.equals(other.med)
                && localPref.equals(other.localPref)
                && aggregatorAsn.equals(other.aggregatorAsn)
                && Arrays.equals(aggregatorAddress, other.aggregatorAddress)
                && Arrays.equals(communities, other.communities)
                && largeCommunities.equals(other.largeCommunities)
                && extendedCommunitiesEqual(other.extendedCommunities)
                && originatorId.equals(other.originatorId)
                && clusterList.equals(other.clusterList)
                && peerRd.equals(other.peerRd)
                && routeTargets.equals(other.routeTargets)
                && Arrays.equals(mplsLabels, other.mplsLabels)
                && Arrays.equals(evpn, other.evpn)
                && Arrays.equals(flowSpec, other.flowSpec)
                && Arrays.equals(srPolicy, other.srPolicy)
                && Arrays.equals(linkState, other.linkState)
                && Arrays.equals(rawNlri, other.rawNlri);
    }

    private boolean extendedCommunitiesEqual(List<byte[]> other) {
        if (extendedCommunities.size() != other.size()) {
            return false;
        }
        for (int i = 0; i < extendedCommunities.size(); i++) {
            if (!Arrays.equals(extendedCommunities.get(i), other.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Hash code consistent with {@link #equals(Object)} (array- and element-aware).
     *
     * @return the hash code
     */
    @Override
    public int hashCode() {
        int result = header.hashCode();
        result = 31 * result + action.hashCode();
        result = 31 * result + Boolean.hashCode(prePolicy);
        result = 31 * result + Boolean.hashCode(locRib);
        result = 31 * result + Boolean.hashCode(ipv4);
        result = 31 * result + Boolean.hashCode(endOfRib);
        result = 31 * result + Boolean.hashCode(addPath);
        result = 31 * result + Arrays.hashCode(prefix);
        result = 31 * result + prefixLength;
        result = 31 * result + pathId.hashCode();
        result = 31 * result + originAsn.hashCode();
        result = 31 * result + Arrays.hashCode(asPath);
        result = 31 * result + asPathSegments.hashCode();
        result = 31 * result + Arrays.hashCode(nextHop);
        result = 31 * result + med.hashCode();
        result = 31 * result + localPref.hashCode();
        result = 31 * result + origin;
        result = 31 * result + Boolean.hashCode(atomicAggregate);
        result = 31 * result + aggregatorAsn.hashCode();
        result = 31 * result + Arrays.hashCode(aggregatorAddress);
        result = 31 * result + Arrays.hashCode(communities);
        result = 31 * result + largeCommunities.hashCode();
        for (byte[] ec : extendedCommunities) {
            result = 31 * result + Arrays.hashCode(ec);
        }
        result = 31 * result + originatorId.hashCode();
        result = 31 * result + clusterList.hashCode();
        result = 31 * result + peerRd.hashCode();
        result = 31 * result + Long.hashCode(vprnId);
        result = 31 * result + routeTargets.hashCode();
        result = 31 * result + Arrays.hashCode(mplsLabels);
        result = 31 * result + Arrays.hashCode(evpn);
        result = 31 * result + Arrays.hashCode(flowSpec);
        result = 31 * result + Arrays.hashCode(srPolicy);
        result = 31 * result + Arrays.hashCode(linkState);
        result = 31 * result + Arrays.hashCode(rawNlri);
        return result;
    }

    /**
     * Renders a diagnostic representation with array contents expanded.
     *
     * @return a human-readable representation
     */
    @Override
    public String toString() {
        StringBuilder ec = new StringBuilder("[");
        for (int i = 0; i < extendedCommunities.size(); i++) {
            if (i > 0) {
                ec.append(", ");
            }
            ec.append(Arrays.toString(extendedCommunities.get(i)));
        }
        ec.append(']');
        return "RouteMonitorMessage["
                + "header=" + header
                + ", action=" + action
                + ", prePolicy=" + prePolicy
                + ", locRib=" + locRib
                + ", ipv4=" + ipv4
                + ", endOfRib=" + endOfRib
                + ", addPath=" + addPath
                + ", prefix=" + Arrays.toString(prefix)
                + ", prefixLength=" + prefixLength
                + ", pathId=" + pathId
                + ", originAsn=" + originAsn
                + ", asPath=" + Arrays.toString(asPath)
                + ", asPathSegments=" + asPathSegments
                + ", nextHop=" + Arrays.toString(nextHop)
                + ", med=" + med
                + ", localPref=" + localPref
                + ", origin=" + origin
                + ", atomicAggregate=" + atomicAggregate
                + ", aggregatorAsn=" + aggregatorAsn
                + ", aggregatorAddress=" + Arrays.toString(aggregatorAddress)
                + ", communities=" + Arrays.toString(communities)
                + ", largeCommunities=" + largeCommunities
                + ", extendedCommunities=" + ec
                + ", originatorId=" + originatorId
                + ", clusterList=" + clusterList
                + ", peerRd=" + peerRd
                + ", vprnId=" + vprnId
                + ", routeTargets=" + routeTargets
                + ", mplsLabels=" + Arrays.toString(mplsLabels)
                + ", evpn=" + Arrays.toString(evpn)
                + ", flowSpec=" + Arrays.toString(flowSpec)
                + ", srPolicy=" + Arrays.toString(srPolicy)
                + ", linkState=" + Arrays.toString(linkState)
                + ", rawNlri=" + Arrays.toString(rawNlri)
                + ']';
    }
}
