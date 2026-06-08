package it.lpworks.jbmp.wire;

/**
 * The effect a {@link RouteMonitorMessage} has on the routing information base.
 *
 * <p>A BGP UPDATE (RFC 4271) either advertises reachability for a set of prefixes or
 * withdraws previously advertised reachability. BMP Route Monitoring (RFC 7854,
 * Section 4.6) carries those UPDATEs verbatim; after enrichment each monitored prefix is
 * reduced to a single {@code RouteAction}.
 */
public enum RouteAction {

    /** The prefix is reachable (NLRI / MP_REACH_NLRI, RFC 4271 / RFC 4760). */
    ANNOUNCE,

    /** The prefix is withdrawn (Withdrawn Routes / MP_UNREACH_NLRI, RFC 4271 / RFC 4760). */
    WITHDRAW
}
