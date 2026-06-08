package it.lpworks.jbmp.protocol.parser.bgp;

import it.lpworks.jbmp.protocol.BmpParseException;
import it.lpworks.jbmp.protocol.bgp.AddPathNlri;
import it.lpworks.jbmp.protocol.bgp.AddressFamily;
import it.lpworks.jbmp.protocol.bgp.EvpnRoute;
import it.lpworks.jbmp.protocol.bgp.FlowSpecComponent;
import it.lpworks.jbmp.protocol.bgp.FlowSpecRule;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bgp.LinkStateNlri;
import it.lpworks.jbmp.protocol.bgp.Nlri;
import it.lpworks.jbmp.protocol.bgp.RawNlri;
import it.lpworks.jbmp.protocol.bgp.RouteDistinguisher;
import it.lpworks.jbmp.protocol.bgp.SrPolicyNlri;
import it.lpworks.jbmp.protocol.bgp.VpnPrefix;
import it.lpworks.jbmp.protocol.io.ByteReader;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Decodes address-family Network Layer Reachability Information (NLRI) from the raw
 * bytes carried by the MP_REACH_NLRI / MP_UNREACH_NLRI path attributes (RFC 4760) and
 * by the IPv4 reachability/withdrawal sections of a BGP UPDATE (RFC 4271 §4.3).
 *
 * <p>Decoding is governed by the {@code (afi, safi)} pair. The supported families are:
 * <ul>
 *   <li>IPv4/IPv6 unicast and multicast (RFC 4271 §4.3, RFC 4760) →
 *       {@link IpPrefix};</li>
 *   <li>MPLS VPN, SAFI 128 (RFC 4364, RFC 8277) → {@link VpnPrefix};</li>
 *   <li>EVPN, AFI 25 / SAFI 70 (RFC 7432) → {@link EvpnRoute};</li>
 *   <li>Flow Specification, SAFI 133/134 (RFC 8955) → {@link FlowSpecRule};</li>
 *   <li>SR Policy, SAFI 73 → {@link SrPolicyNlri};</li>
 *   <li>BGP-LS, AFI 16388 / SAFI 71/72 (RFC 7752) → {@link LinkStateNlri}.</li>
 * </ul>
 *
 * <p>ADD-PATH (RFC 7911): when {@code addPath} is set, the prefix-style families
 * (unicast/multicast and MPLS VPN) carry a leading 4-octet Path Identifier per NLRI;
 * each decoded entry is wrapped in {@link AddPathNlri}.
 *
 * <p><strong>Zero data loss.</strong> Any family that is not modelled, and any element
 * that cannot be fully decoded (for example because a length field over-runs the
 * buffer), never causes bytes to be discarded: the undecodable remainder is preserved
 * as a {@link RawNlri} carrying the supplied {@code (afi, safi)}, and parsing of the
 * sequence stops at that point. This makes {@link #decode} total for any input.
 *
 * <p>Multi-byte integers are unsigned and read in network byte order via
 * {@link ByteReader}; callers must remember Java has no unsigned primitives.
 */
public final class NlriDecoder {

    /** ADD-PATH Path Identifier width in octets (RFC 7911 §3). */
    private static final int PATH_ID_LEN = 4;

    /** Width of one MPLS label entry in octets (RFC 3032). */
    private static final int LABEL_LEN = 3;

    /** Width of a Route Distinguisher in octets (RFC 4364 §4.2). */
    private static final int RD_LEN = 8;

    /** Bit width of one MPLS label entry. */
    private static final int LABEL_BITS = LABEL_LEN * 8;

    /** Bit width of a Route Distinguisher. */
    private static final int RD_BITS = RD_LEN * 8;

    /** Safety cap on the MPLS label stack depth (RFC 8277). */
    private static final int MAX_LABELS = 5;

    private NlriDecoder() {
        // Static utility; not instantiable.
    }

    /**
     * Decodes a sequence of NLRIs for the given address family.
     *
     * @param afi       the Address Family Identifier (see {@link AddressFamily})
     * @param safi      the Subsequent Address Family Identifier (see {@link AddressFamily})
     * @param nlriBytes the raw NLRI bytes (never {@code null}); an empty array yields an
     *                  empty list
     * @param addPath   whether ADD-PATH (RFC 7911) framing is in effect for prefix-style
     *                  families
     * @return an immutable list of decoded NLRIs; undecodable input is preserved as
     *         {@link RawNlri} so no bytes are ever lost
     */
    public static List<Nlri> decode(int afi, int safi, byte[] nlriBytes, boolean addPath) {
        if (nlriBytes == null || nlriBytes.length == 0) {
            return List.of();
        }
        ByteReader reader = new ByteReader(nlriBytes);
        List<Nlri> out = new ArrayList<>();

        boolean unicastLike = (afi == AddressFamily.AFI_IPV4 || afi == AddressFamily.AFI_IPV6)
                && (safi == AddressFamily.SAFI_UNICAST || safi == AddressFamily.SAFI_MULTICAST);
        boolean mplsVpn = (afi == AddressFamily.AFI_IPV4 || afi == AddressFamily.AFI_IPV6)
                && safi == AddressFamily.SAFI_MPLS_VPN;
        boolean evpn = afi == AddressFamily.AFI_L2VPN && safi == AddressFamily.SAFI_EVPN;
        boolean flowSpec = safi == AddressFamily.SAFI_FLOWSPEC
                || safi == AddressFamily.SAFI_FLOWSPEC_VPN;
        boolean srPolicy = safi == AddressFamily.SAFI_SR_POLICY;
        boolean bgpLs = afi == AddressFamily.AFI_BGP_LS
                && (safi == AddressFamily.SAFI_BGP_LS || safi == AddressFamily.SAFI_BGP_LS_VPN);

        if (unicastLike) {
            decodeUnicast(afi, safi, reader, addPath, out);
        } else if (mplsVpn) {
            decodeMplsVpn(afi, safi, reader, addPath, out);
        } else if (evpn) {
            decodeEvpn(afi, safi, reader, out);
        } else if (flowSpec) {
            decodeFlowSpec(afi, safi, reader, out);
        } else if (srPolicy) {
            // SR Policy: structured parsing optional; preserve the NLRI verbatim.
            out.add(new SrPolicyNlri(nlriBytes));
        } else if (bgpLs) {
            decodeBgpLs(afi, safi, reader, out);
        } else {
            // Unmodelled family: keep everything raw.
            out.add(new RawNlri(afi, safi, nlriBytes));
        }
        return List.copyOf(out);
    }

    // ------------------------------------------------------------------
    // IPv4/IPv6 unicast & multicast (RFC 4271 §4.3, RFC 4760)
    // ------------------------------------------------------------------

    private static void decodeUnicast(int afi, int safi, ByteReader reader, boolean addPath,
                                      List<Nlri> out) {
        int addressLen = (afi == AddressFamily.AFI_IPV4) ? 4 : 16;
        int maxBits = addressLen * 8;
        while (reader.readableBytes() > 0) {
            int startPos = reader.position();
            try {
                long pathId = 0;
                if (addPath) {
                    pathId = reader.readUint32();
                }
                int prefixBits = reader.readUint8();
                if (prefixBits > maxBits) {
                    throw new BmpParseException(
                            "Prefix length " + prefixBits + " bits exceeds " + maxBits
                                    + " for AFI " + afi, startPos);
                }
                int prefixBytes = (prefixBits + 7) / 8;
                byte[] significant = reader.readBytes(prefixBytes);
                byte[] address = new byte[addressLen];
                System.arraycopy(significant, 0, address, 0, prefixBytes);
                IpPrefix prefix = new IpPrefix(toInetAddress(address), prefixBits);
                out.add(addPath ? new AddPathNlri(pathId, prefix) : prefix);
            } catch (BmpParseException | IllegalArgumentException e) {
                captureRemainder(afi, safi, reader, startPos, out);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // MPLS VPN, SAFI 128 (RFC 4364, RFC 8277)
    // ------------------------------------------------------------------

    private static void decodeMplsVpn(int afi, int safi, ByteReader reader, boolean addPath,
                                      List<Nlri> out) {
        int addressLen = (afi == AddressFamily.AFI_IPV4) ? 4 : 16;
        while (reader.readableBytes() > 0) {
            int startPos = reader.position();
            try {
                long pathId = 0;
                if (addPath) {
                    pathId = reader.readUint32();
                }
                // Total length, in BITS, covering label stack + RD + prefix.
                int totalBits = reader.readUint8();
                int totalBytes = (totalBits + 7) / 8;
                ByteReader body = reader.slice(totalBytes);

                // MPLS label stack: 3-byte entries until bottom-of-stack (cap MAX_LABELS).
                List<Long> labels = new ArrayList<>();
                int labelCount = 0;
                boolean bottom = false;
                while (!bottom && body.readableBytes() >= LABEL_LEN && labelCount < MAX_LABELS) {
                    int b0 = body.readUint8();
                    int b1 = body.readUint8();
                    int b2 = body.readUint8();
                    long label = ((long) (b0 & 0xFF) << 12)
                            | ((long) (b1 & 0xFF) << 4)
                            | ((b2 & 0xFF) >> 4);
                    labels.add(label);
                    labelCount++;
                    bottom = (b2 & 0x01) != 0;
                }

                // 8-octet Route Distinguisher (type from first 2 octets, value = octets 2..8).
                byte[] rdBytes = body.readBytes(RD_LEN);
                int rdType = ((rdBytes[0] & 0xFF) << 8) | (rdBytes[1] & 0xFF);
                RouteDistinguisher rd =
                        new RouteDistinguisher(rdType, Arrays.copyOfRange(rdBytes, 2, RD_LEN));

                // Residual bits are the inner IP prefix.
                int prefixBits = totalBits - (labelCount * LABEL_BITS) - RD_BITS;
                if (prefixBits < 0 || prefixBits > addressLen * 8) {
                    throw new BmpParseException(
                            "Computed VPN prefix length " + prefixBits + " bits is out of range",
                            startPos);
                }
                int prefixBytes = (prefixBits + 7) / 8;
                byte[] significant = body.readBytes(prefixBytes);
                byte[] address = new byte[addressLen];
                System.arraycopy(significant, 0, address, 0, prefixBytes);
                IpPrefix prefix = new IpPrefix(toInetAddress(address), prefixBits);

                long[] labelArray = new long[labels.size()];
                for (int i = 0; i < labelArray.length; i++) {
                    labelArray[i] = labels.get(i);
                }
                VpnPrefix vpn = new VpnPrefix(rd, labelArray, prefix);
                out.add(addPath ? new AddPathNlri(pathId, vpn) : vpn);
            } catch (BmpParseException | IllegalArgumentException e) {
                captureRemainder(afi, safi, reader, startPos, out);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // EVPN, AFI 25 / SAFI 70 (RFC 7432 §7)
    // ------------------------------------------------------------------

    private static void decodeEvpn(int afi, int safi, ByteReader reader, List<Nlri> out) {
        while (reader.readableBytes() > 0) {
            int startPos = reader.position();
            try {
                int routeType = reader.readUint8();
                int length = reader.readUint8();
                byte[] value = reader.readBytes(length);
                out.add(new EvpnRoute(routeType, value));
            } catch (BmpParseException | IllegalArgumentException e) {
                captureRemainder(afi, safi, reader, startPos, out);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // Flow Specification, SAFI 133/134 (RFC 8955)
    // ------------------------------------------------------------------

    private static void decodeFlowSpec(int afi, int safi, ByteReader reader, List<Nlri> out) {
        while (reader.readableBytes() > 0) {
            int startPos = reader.position();
            try {
                // NLRI length: 1 octet if < 0xF0, otherwise 2 octets (RFC 8955 §4).
                int first = reader.readUint8();
                int ruleLength;
                if (first < 0xF0) {
                    ruleLength = first;
                } else {
                    int second = reader.readUint8();
                    ruleLength = ((first & 0x0F) << 8) | second;
                }
                byte[] body = reader.readBytes(ruleLength);
                List<FlowSpecComponent> components = decodeFlowSpecComponents(safi, body);
                out.add(new FlowSpecRule(safi, body, components));
            } catch (BmpParseException | IllegalArgumentException e) {
                captureRemainder(afi, safi, reader, startPos, out);
                return;
            }
        }
    }

    /**
     * Splits a Flow Specification rule body into components, preceded by an 8-octet RD
     * for the VPN variant. Each component is {@code [type(1), value...]}; the value of
     * the prefix component types (1, 2) is {@code [prefixLen(1), ceil(prefixLen/8)]}
     * octets, and numeric-match types are sequences of {@code [op(1), value(1<<len)]}
     * pairs terminated by an operator with the end-of-list bit set (RFC 8955 §4.2.1.1).
     * If a component cannot be reliably delimited, the remaining bytes are kept as one
     * raw component so no data is lost.
     */
    private static List<FlowSpecComponent> decodeFlowSpecComponents(int safi, byte[] body) {
        List<FlowSpecComponent> components = new ArrayList<>();
        ByteReader r = new ByteReader(body);

        if (safi == AddressFamily.SAFI_FLOWSPEC_VPN) {
            // VPN flowspec carries a leading 8-octet RD; preserve it as a synthetic
            // component (type 0 is unassigned in the component registry, RFC 8955 §4.2.1).
            if (r.readableBytes() < RD_LEN) {
                components.add(new FlowSpecComponent(0, r.readBytes(r.readableBytes())));
                return components;
            }
            components.add(new FlowSpecComponent(0, r.readBytes(RD_LEN)));
        }

        while (r.readableBytes() > 0) {
            int compStart = r.position();
            try {
                int type = r.readUint8();
                byte[] value = decodeFlowSpecComponentValue(type, r);
                components.add(new FlowSpecComponent(type, value));
            } catch (BmpParseException | IllegalArgumentException e) {
                // Cannot delimit reliably: keep the remainder as one raw component.
                r.position(compStart);
                byte[] rest = r.readBytes(r.readableBytes());
                components.add(new FlowSpecComponent(0xFF, rest));
                break;
            }
        }
        return components;
    }

    /**
     * Reads the value of a single Flow Specification component starting just after its
     * type octet, returning the value bytes (excluding the type).
     */
    private static byte[] decodeFlowSpecComponentValue(int type, ByteReader r) {
        int valueStart = r.position();
        if (type == 1 || type == 2) {
            // Destination/Source Prefix: prefix-length octet then ceil(len/8) octets.
            int prefixLen = r.readUint8();
            int prefixBytes = (prefixLen + 7) / 8;
            r.skip(prefixBytes);
        } else {
            // Numeric op/value pairs: each op octet has end-of-list bit 0x80 and a
            // 2-bit length field (bits 0x30) giving value width 1<<len (RFC 8955 §4.2.1.1).
            boolean end = false;
            while (!end) {
                int op = r.readUint8();
                int len = 1 << ((op >> 4) & 0x03);
                r.skip(len);
                end = (op & 0x80) != 0;
            }
        }
        int valueEnd = r.position();
        r.position(valueStart);
        byte[] value = r.readBytes(valueEnd - valueStart);
        return value;
    }

    // ------------------------------------------------------------------
    // BGP-LS, AFI 16388 / SAFI 71/72 (RFC 7752 §3.2)
    // ------------------------------------------------------------------

    private static void decodeBgpLs(int afi, int safi, ByteReader reader, List<Nlri> out) {
        while (reader.readableBytes() > 0) {
            int startPos = reader.position();
            try {
                int nlriType = reader.readUint16();
                int totalLength = reader.readUint16();
                byte[] value = reader.readBytes(totalLength);
                out.add(new LinkStateNlri(nlriType, value));
            } catch (BmpParseException | IllegalArgumentException e) {
                captureRemainder(afi, safi, reader, startPos, out);
                return;
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /**
     * Captures every byte from {@code fromPos} to the reader's limit as a single
     * {@link RawNlri}, guaranteeing no data is lost when an element cannot be decoded.
     */
    private static void captureRemainder(int afi, int safi, ByteReader reader, int fromPos,
                                         List<Nlri> out) {
        reader.position(fromPos);
        int remaining = reader.readableBytes();
        if (remaining > 0) {
            byte[] rest = reader.readBytes(remaining);
            out.add(new RawNlri(afi, safi, rest));
        }
    }

    /**
     * Builds an {@link InetAddress} from a 4- or 16-octet array, narrowing to
     * {@link Inet4Address} for IPv4 so the resulting {@link IpPrefix} reports the
     * correct AFI.
     */
    private static InetAddress toInetAddress(byte[] address) {
        try {
            return InetAddress.getByAddress(address);
        } catch (UnknownHostException e) {
            // Only thrown for an illegal length; map to a parse failure for graceful
            // raw capture by the caller.
            throw new BmpParseException("Illegal address length: " + address.length, e);
        }
    }
}
