/**
 * Parsers for the BGP-4 UPDATE message (RFC 4271 §4.3) and its path attributes.
 *
 * <p>The public entry point is
 * {@link it.lpworks.jbmp.protocol.parser.bgp.BgpUpdateParser}, which frames a complete
 * BGP message (RFC 4271 §4.1) and decodes the UPDATE body into an immutable
 * {@link it.lpworks.jbmp.protocol.bgp.BgpUpdate}. Path-attribute dispatch lives in the
 * package-private {@code PathAttributeParser}; AS_PATH parsing and the RFC 6793
 * AS4_PATH / AS4_AGGREGATOR merge live in {@code AsPathParser}; the shared
 * length-prefixed IPv4 prefix decoder lives in {@code PrefixReader}.
 *
 * <p>Tolerance is governed by {@link it.lpworks.jbmp.protocol.parser.ParseMode}:
 * framing errors are always fatal, while recoverable content errors either throw
 * (STRICT) or degrade gracefully by preserving everything decoded so far (LENIENT),
 * following RFC 4271 §6.3 resilience.
 */
package it.lpworks.jbmp.protocol.parser.bgp;
