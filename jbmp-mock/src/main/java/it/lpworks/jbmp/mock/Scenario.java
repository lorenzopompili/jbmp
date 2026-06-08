package it.lpworks.jbmp.mock;

/**
 * The traffic-generation scenarios the mock can play.
 *
 * <p>Every scenario begins with the same session preamble — an Initiation message, a
 * Peer Up Notification per peer, the initial table dump and its End-of-RIB markers, and
 * a Statistics Report per peer. The scenarios differ only in what follows the dump and,
 * for {@link #STRESS}, in how richly each announcement is attributed.
 */
public enum Scenario {

    /**
     * The session preamble and initial table dump only; no post-dump traffic. Suitable
     * for exercising a collector's RIB-import path without ongoing churn.
     */
    INITIAL_DUMP("initial-dump"),

    /**
     * The initial dump followed by continuous incremental announce/withdraw churn at the
     * configured rate (RFC 7854 §4.6 Route Monitoring updates).
     */
    INCREMENTAL("incremental"),

    /**
     * The full lifecycle: the initial dump, incremental churn, and a graceful teardown
     * (a Peer Down Notification per peer and a Termination message) at the end.
     */
    FULL_LIFECYCLE("full-lifecycle"),

    /**
     * The full lifecycle <em>plus</em> the complete BGP attribute mix on every
     * announcement: multi-segment AS_PATHs (with occasional AS_SET / AS_CONFED_SEQUENCE
     * segments, RFC 4271 §5.1.2 / RFC 5065), ORIGIN, MED, LOCAL_PREF, NEXT_HOP,
     * ATOMIC_AGGREGATE + AGGREGATOR on a fraction (RFC 4271 §5.1.6 / §5.1.7), standard,
     * large and extended communities (RFC 1997, RFC 8092, RFC 4360), route-reflector
     * attributes (ORIGINATOR_ID + CLUSTER_LIST, RFC 4456) on a fraction, and a fraction of
     * multiprotocol routes — L3VPN (RFC 4364), EVPN (RFC 7432), Flow Specification
     * (RFC 8955), SR Policy and BGP-LS (RFC 7752) — so every address family appears in the
     * stream. This is the scenario to drive jBMP's own end-to-end pipeline across every
     * structured column.
     */
    STRESS("stress");

    private final String id;

    Scenario(String id) {
        this.id = id;
    }

    /**
     * Returns the configuration identifier for this scenario.
     *
     * @return the lowercase, hyphenated scenario id used in {@code jbmp.mock.scenario}
     */
    public String id() {
        return id;
    }

    /**
     * Reports whether this scenario emits incremental churn after the initial dump.
     *
     * @return {@code true} for {@link #INCREMENTAL}, {@link #FULL_LIFECYCLE} and
     *         {@link #STRESS}
     */
    public boolean hasIncrementalChurn() {
        return this == INCREMENTAL || this == FULL_LIFECYCLE || this == STRESS;
    }

    /**
     * Reports whether this scenario tears the session down at the end (Peer Down per
     * peer plus a Termination message).
     *
     * @return {@code true} for {@link #FULL_LIFECYCLE} and {@link #STRESS}
     */
    public boolean hasTeardown() {
        return this == FULL_LIFECYCLE || this == STRESS;
    }

    /**
     * Reports whether this scenario emits the complete multiprotocol attribute mix on its
     * announcements (the multiprotocol families — L3VPN, EVPN, Flow Specification, SR
     * Policy and BGP-LS — in addition to the richly-attributed IPv4-unicast routes that
     * every scenario already produces).
     *
     * @return {@code true} for {@link #STRESS}
     */
    public boolean hasFullAttributeMix() {
        return this == STRESS;
    }

    /**
     * Resolves a scenario from its configuration identifier.
     *
     * @param id the scenario id (case-insensitive); may be {@code null}
     * @return the matching scenario, or {@link #INITIAL_DUMP} when {@code id} is unknown
     */
    public static Scenario fromId(String id) {
        if (id != null) {
            for (Scenario scenario : values()) {
                if (scenario.id.equalsIgnoreCase(id)) {
                    return scenario;
                }
            }
        }
        return INITIAL_DUMP;
    }
}
