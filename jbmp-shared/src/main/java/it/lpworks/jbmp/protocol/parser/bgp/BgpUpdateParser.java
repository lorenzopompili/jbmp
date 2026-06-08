package it.lpworks.jbmp.protocol.parser.bgp;

import it.lpworks.jbmp.protocol.BmpParseException;
import it.lpworks.jbmp.protocol.bgp.BgpUpdate;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.io.ByteReader;
import it.lpworks.jbmp.protocol.parser.ParseMode;

import java.util.List;

/**
 * Parses a complete BGP-4 UPDATE message (RFC 4271 §4.3) into a {@link BgpUpdate}.
 *
 * <p>The input is a full BGP message including its 19-octet header (RFC 4271 §4.1):
 * a 16-octet marker, a two-octet length and a one-octet type. Only the UPDATE type
 * (2) is accepted; any other type raises {@link BmpParseException}.
 *
 * <p>The UPDATE body is framed as a two-octet Withdrawn Routes Length followed by that
 * many octets of withdrawn IPv4 prefixes, a two-octet Total Path Attribute Length
 * followed by that many octets of path attributes, and finally the remaining octets as
 * the advertised IPv4 NLRI. Multiprotocol families are carried inside MP_REACH_NLRI /
 * MP_UNREACH_NLRI attributes (RFC 4760) rather than in the IPv4 withdrawn/NLRI fields.
 *
 * <p>The {@link ParseMode} governs only recoverable, content-level errors. Framing
 * errors (truncated header, lengths that overrun the message) are always fatal. In
 * {@link ParseMode#LENIENT}, a malformed path attribute or prefix stops that section
 * while preserving everything decoded so far (RFC 4271 §6.3 resilience); in
 * {@link ParseMode#STRICT} it raises {@link BmpParseException}.
 */
public final class BgpUpdateParser {

    /** Length, in octets, of the BGP message marker (RFC 4271 §4.1). */
    private static final int MARKER_LENGTH = 16;

    /** Length, in octets, of the full BGP message header (marker + length + type). */
    private static final int HEADER_LENGTH = 19;

    /** Minimum legal BGP message length (RFC 4271 §4.1). */
    private static final int MIN_MESSAGE_LENGTH = HEADER_LENGTH;

    /** Maximum legal BGP message length (RFC 4271 §4.1). */
    private static final int MAX_MESSAGE_LENGTH = 4096;

    /** The UPDATE message type code (RFC 4271 §4.1). */
    private static final int TYPE_UPDATE = 2;

    private BgpUpdateParser() {
        // Entry-point holder; not instantiable.
    }

    /**
     * Parses a complete BGP UPDATE message.
     *
     * @param bgpMessage a reader positioned at the start of a complete BGP message
     *                   (16-octet marker, length, type, then the UPDATE body)
     * @param mode       the parse tolerance for recoverable, content-level errors
     * @param asPath2Byte whether the AS_PATH attribute carries two-octet AS numbers; when
     *                    {@code true}, any AS4_PATH / AS4_AGGREGATOR present is merged into
     *                    AS_PATH / AGGREGATOR per RFC 6793
     * @return the decoded UPDATE
     * @throws BmpParseException if the header is truncated, the length is illegal, the
     *                           type is not UPDATE, the body overruns the message, or
     *                           (in {@link ParseMode#STRICT}) a content field is malformed
     */
    public static BgpUpdate parse(ByteReader bgpMessage, ParseMode mode, boolean asPath2Byte) {
        if (bgpMessage == null) {
            throw new BmpParseException("BGP message reader must not be null");
        }
        if (mode == null) {
            throw new BmpParseException("ParseMode must not be null");
        }

        // --- BGP message header (RFC 4271 §4.1): marker(16), length(2), type(1). ---
        bgpMessage.require(HEADER_LENGTH);
        bgpMessage.skip(MARKER_LENGTH); // Marker is not interpreted.
        int messageLength = bgpMessage.readUint16();
        int type = bgpMessage.readUint8();

        if (messageLength < MIN_MESSAGE_LENGTH || messageLength > MAX_MESSAGE_LENGTH) {
            throw new BmpParseException(
                    "Illegal BGP message length " + messageLength + " (must be in ["
                            + MIN_MESSAGE_LENGTH + ", " + MAX_MESSAGE_LENGTH + "])",
                    bgpMessage.position());
        }
        if (type != TYPE_UPDATE) {
            throw new BmpParseException(
                    "Expected BGP UPDATE (type " + TYPE_UPDATE + ") but found type " + type,
                    bgpMessage.position());
        }

        // The body spans (messageLength - HEADER_LENGTH) octets and must be present.
        int bodyLength = messageLength - HEADER_LENGTH;
        ByteReader body = bgpMessage.slice(bodyLength);

        return parseBody(body, mode, asPath2Byte);
    }

    /**
     * Parses the UPDATE body: withdrawn routes, path attributes and NLRI.
     *
     * @param body        a reader spanning exactly the UPDATE body
     * @param mode        the parse tolerance
     * @param asPath2Byte whether AS_PATH uses two-octet AS numbers (drives AS4 merge)
     * @return the decoded UPDATE
     * @throws BmpParseException if a length field overruns the body, or (in
     *                           {@link ParseMode#STRICT}) a content field is malformed
     */
    private static BgpUpdate parseBody(ByteReader body, ParseMode mode, boolean asPath2Byte) {
        boolean strict = mode == ParseMode.STRICT;

        // --- Withdrawn Routes (RFC 4271 §4.3). ---
        int withdrawnLength = body.readUint16();
        ByteReader withdrawnReader = sliceOrThrow(body, withdrawnLength, "Withdrawn Routes");
        List<IpPrefix> withdrawnRoutes = PrefixReader.readPrefixes(withdrawnReader, strict);

        // --- Total Path Attribute Length + Path Attributes (RFC 4271 §4.3). ---
        int pathAttrLength = body.readUint16();
        ByteReader pathAttrReader = sliceOrThrow(body, pathAttrLength, "Path Attributes");
        List<PathAttribute> pathAttributes =
                PathAttributeParser.parse(pathAttrReader, mode, asPath2Byte);

        // --- NLRI: the remaining body octets (RFC 4271 §4.3). ---
        List<IpPrefix> nlri = PrefixReader.readPrefixes(body, strict);

        return new BgpUpdate(withdrawnRoutes, pathAttributes, nlri);
    }

    /**
     * Slices {@code length} octets from {@code body}, raising a framing-specific
     * {@link BmpParseException} if the field overruns the body.
     *
     * @param body   the body reader
     * @param length the declared field length
     * @param field  the field name for diagnostics
     * @return a reader spanning exactly the field
     * @throws BmpParseException if the field overruns the body (always fatal framing)
     */
    private static ByteReader sliceOrThrow(ByteReader body, int length, String field) {
        if (length > body.readableBytes()) {
            throw new BmpParseException(
                    field + " length " + length + " overruns UPDATE body ("
                            + body.readableBytes() + " octet(s) remaining)", body.position());
        }
        return body.slice(length);
    }
}
