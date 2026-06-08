package it.lpworks.jbmp.protocol.bmp;

/**
 * A decoded BMP message body.
 *
 * <p>See RFC 7854 §4. This is a closed hierarchy of the seven BMP message types.
 * The fixed common header is modelled separately by {@link BmpCommonHeader}; this
 * interface represents the typed body.
 */
public sealed interface BmpMessage
        permits InitiationMessage,
                TerminationMessage,
                PeerUpNotification,
                PeerDownNotification,
                RouteMonitoring,
                StatisticsReport,
                RouteMirroring {

    /**
     * Returns the message type discriminator.
     *
     * @return the BMP message type
     */
    BmpMessageType type();
}
