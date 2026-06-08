package it.lpworks.jbmp.wire;

/**
 * The lifecycle transition reported by a {@link PeerEventMessage}.
 *
 * <p>BMP signals peering session changes with the Peer Up Notification and Peer Down
 * Notification messages (RFC 7854, Sections 4.10 and 4.9). After enrichment those two
 * BMP message types collapse onto this enum.
 */
public enum PeerEventType {

    /** The monitored BGP session reached the Established state (Peer Up, RFC 7854 §4.10). */
    UP,

    /** The monitored BGP session left the Established state (Peer Down, RFC 7854 §4.9). */
    DOWN
}
