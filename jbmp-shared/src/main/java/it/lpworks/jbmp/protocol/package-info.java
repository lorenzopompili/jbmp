/**
 * BGP Monitoring Protocol (RFC 7854) and BGP-4 (RFC 4271) message model, parsers,
 * builders and the binary wire codec used to transport parsed messages.
 *
 * <p>This module is pure Java with no framework dependencies and may be used as a
 * standalone library. The parsing layer is allocation-conscious: the high-volume
 * route-monitoring path is designed to be parsed and re-serialized with minimal
 * intermediate garbage, while lower-frequency message types use the immutable
 * record model for clarity.
 */
package it.lpworks.jbmp.protocol;
