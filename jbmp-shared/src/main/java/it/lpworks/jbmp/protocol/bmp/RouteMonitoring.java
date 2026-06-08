package it.lpworks.jbmp.protocol.bmp;

import it.lpworks.jbmp.protocol.bgp.BgpUpdate;

import java.util.Objects;

/**
 * A BMP Route Monitoring message.
 *
 * <p>See RFC 7854 §4.6. Carries a single BGP UPDATE observed from a monitored peer,
 * together with that peer's per-peer header.
 *
 * @param peerHeader the per-peer header
 * @param update     the encapsulated BGP UPDATE
 */
public record RouteMonitoring(PerPeerHeader peerHeader, BgpUpdate update) implements BmpMessage {

    /**
     * Validates the fields.
     */
    public RouteMonitoring {
        Objects.requireNonNull(peerHeader, "peerHeader");
        Objects.requireNonNull(update, "update");
    }

    @Override
    public BmpMessageType type() {
        return BmpMessageType.ROUTE_MONITORING;
    }
}
