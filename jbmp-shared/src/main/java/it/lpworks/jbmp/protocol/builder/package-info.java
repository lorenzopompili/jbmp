/**
 * Builders that encode the BMP/BGP domain model back to its on-wire byte form — the
 * inverse of the parsers in {@code it.lpworks.jbmp.protocol.parser}.
 *
 * <p>{@link it.lpworks.jbmp.protocol.builder.BgpUpdateBuilder} encodes a complete,
 * framed BGP-4 UPDATE message (RFC 4271 §4.3): marker, length, type, then the
 * withdrawn routes, path attributes and NLRI. Attribute flags are set to their
 * RFC-mandated O/T/P bits and promoted to extended length (RFC 4271 §4.3) when a value
 * exceeds 255 octets.
 *
 * <p>{@link it.lpworks.jbmp.protocol.builder.BmpMessageBuilder} provides one builder
 * per BMP message type (RFC 7854 §4), each producing a complete message with the
 * 6-octet common header and a back-patched total length. The per-peer header
 * (RFC 7854 §4.2) is encoded including the IPv4-in-the-trailing-four-octets quirk.
 *
 * <p>Both builders are byte-exact inverses of the corresponding parsers, so a
 * build-then-parse round trip reproduces the original model. All encoding uses
 * {@link it.lpworks.jbmp.protocol.io.ByteWriter}.
 */
package it.lpworks.jbmp.protocol.builder;
