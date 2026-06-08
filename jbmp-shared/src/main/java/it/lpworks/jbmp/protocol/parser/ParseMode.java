package it.lpworks.jbmp.protocol.parser;

/**
 * Controls how tolerant a parser is of malformed input.
 *
 * <p>BMP framing errors (a truncated common header, an impossible message length)
 * are always fatal and raise {@link it.lpworks.jbmp.protocol.BmpParseException}
 * regardless of mode. The mode governs the recoverable, content-level cases —
 * chiefly BGP path-attribute parsing (RFC 4271 §6.3 treat-as-withdraw / attribute
 * discard semantics).
 *
 * <ul>
 *   <li>{@link #STRICT} — any malformed element raises an exception. Use in tests and
 *       conformance checks.</li>
 *   <li>{@link #LENIENT} — recoverable errors degrade gracefully: a malformed or
 *       truncated path attribute stops attribute parsing while preserving the
 *       attributes already decoded, rather than discarding the whole message. Use in
 *       production ingest, where surviving a single bad message matters more than
 *       rejecting it.</li>
 * </ul>
 */
public enum ParseMode {

    /** Fail on any malformed element. */
    STRICT,

    /** Degrade gracefully on recoverable, content-level errors. */
    LENIENT
}
