package it.lpworks.jbmp.protocol.parser.bgp;

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
import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link NlriDecoder} covering every supported address family, the
 * ADD-PATH (RFC 7911) framing, and the zero-data-loss fallback for malformed or
 * unmodelled input.
 */
class NlriDecoderTest {

    /** Parses a whitespace-tolerant hex string into a {@code byte[]}. */
    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.replaceAll("\\s", ""));
    }

    // ------------------------------------------------------------------
    // IPv4 unicast (RFC 4271 §4.3)
    // ------------------------------------------------------------------

    @Test
    void decodesIpv4UnicastPrefixes() {
        // 24-bit 10.0.0.0/24, then 16-bit 192.168.0.0/16, then 0-bit default route.
        byte[] bytes = hex("18 0A 00 00  10 C0 A8  00");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_UNICAST, bytes, false);

        assertThat(result).hasSize(3);
        assertThat(result).allSatisfy(n -> assertThat(n).isInstanceOf(IpPrefix.class));
        assertThat(((IpPrefix) result.get(0)).asCidr()).isEqualTo("10.0.0.0/24");
        assertThat(((IpPrefix) result.get(1)).asCidr()).isEqualTo("192.168.0.0/16");
        assertThat(((IpPrefix) result.get(2)).asCidr()).isEqualTo("0.0.0.0/0");
        assertThat(result.get(0).afi()).isEqualTo(AddressFamily.AFI_IPV4);
        assertThat(result.get(0).safi()).isEqualTo(AddressFamily.SAFI_UNICAST);
    }

    @Test
    void decodesIpv4UnicastWithAddPath() {
        // pathId=1, 10.0.0.0/24 ; pathId=2, 10.1.0.0/24
        byte[] bytes = hex("00000001 18 0A0000   00000002 18 0A0100");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_UNICAST, bytes, true);

        assertThat(result).hasSize(2);
        assertThat(result).allSatisfy(n -> assertThat(n).isInstanceOf(AddPathNlri.class));
        AddPathNlri first = (AddPathNlri) result.get(0);
        assertThat(first.pathId()).isEqualTo(1L);
        assertThat(((IpPrefix) first.nlri()).asCidr()).isEqualTo("10.0.0.0/24");
        AddPathNlri second = (AddPathNlri) result.get(1);
        assertThat(second.pathId()).isEqualTo(2L);
        assertThat(((IpPrefix) second.nlri()).asCidr()).isEqualTo("10.1.0.0/24");
        // AFI/SAFI delegate to the wrapped NLRI.
        assertThat(first.afi()).isEqualTo(AddressFamily.AFI_IPV4);
        assertThat(first.safi()).isEqualTo(AddressFamily.SAFI_UNICAST);
    }

    // ------------------------------------------------------------------
    // IPv6 unicast (RFC 4760)
    // ------------------------------------------------------------------

    @Test
    void decodesIpv6UnicastPrefixes() {
        // 2001:db8::/32 -> prefixLen 0x20 (32 bits), 4 significant octets 20 01 0d b8
        byte[] bytes = hex("20 2001 0DB8");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV6, AddressFamily.SAFI_UNICAST, bytes, false);

        assertThat(result).hasSize(1);
        IpPrefix prefix = (IpPrefix) result.get(0);
        assertThat(prefix.prefixLength()).isEqualTo(32);
        assertThat(prefix.asCidr()).isEqualTo("2001:db8:0:0:0:0:0:0/32");
        assertThat(prefix.afi()).isEqualTo(AddressFamily.AFI_IPV6);
    }

    @Test
    void decodesIpv6UnicastWithAddPath() {
        byte[] bytes = hex("0000000A 20 2001 0DB8");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV6, AddressFamily.SAFI_UNICAST, bytes, true);

        assertThat(result).hasSize(1);
        AddPathNlri wrapped = (AddPathNlri) result.get(0);
        assertThat(wrapped.pathId()).isEqualTo(10L);
        assertThat(((IpPrefix) wrapped.nlri()).prefixLength()).isEqualTo(32);
        assertThat(wrapped.afi()).isEqualTo(AddressFamily.AFI_IPV6);
    }

    @Test
    void decodesIpv4Multicast() {
        byte[] bytes = hex("18 0A0000");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_MULTICAST, bytes, false);
        assertThat(result).hasSize(1);
        assertThat(((IpPrefix) result.get(0)).asCidr()).isEqualTo("10.0.0.0/24");
    }

    // ------------------------------------------------------------------
    // MPLS VPN, SAFI 128 (RFC 4364 / RFC 8277)
    // ------------------------------------------------------------------

    @Test
    void decodesL3VpnWithLabelStackRdAndPrefix() {
        // total bits = 24 (label) + 64 (RD) + 24 (prefix /24) = 112 -> 0x70
        // label 16 BoS: 00 01 01  -> value 16, bottom-of-stack set
        // RD type 0, asn 100, num 200: 0000 0064 000000C8
        // prefix 10.0.0.0/24: 0A 00 00
        byte[] bytes = hex("70  000101  0000 0064 000000C8  0A0000");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_MPLS_VPN, bytes, false);

        assertThat(result).hasSize(1);
        VpnPrefix vpn = (VpnPrefix) result.get(0);
        // Label bit math: ((0x00)<<12)|((0x01)<<4)|((0x01)>>4) = 16
        assertThat(vpn.mplsLabels()).containsExactly(16L);
        assertThat(vpn.rd().type()).isEqualTo(0);
        assertThat(vpn.rd().asText()).isEqualTo("100:200");
        assertThat(vpn.prefix().asCidr()).isEqualTo("10.0.0.0/24");
        assertThat(vpn.afi()).isEqualTo(AddressFamily.AFI_IPV4);
        assertThat(vpn.safi()).isEqualTo(AddressFamily.SAFI_MPLS_VPN);
    }

    @Test
    void decodesL3VpnLabelBitMathForLargeLabel() {
        // label value 1048575 (0xFFFFF) with BoS set.
        // 20-bit 0xFFFFF -> bytes: b0=0xFF b1=0xFF (top16) b2 high nibble=0xF, BoS bit=1 -> b2=0xF1
        // total bits = 24 + 64 + 8 (/8 prefix) = 96 -> 0x60
        // RD type 1, ip 1.1.1.1, num 5: type 0001, value 01010101 0005
        // prefix 10.0.0.0/8 -> 0A
        byte[] bytes = hex("60  FFFFF1  0001 01010101 0005  0A");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_MPLS_VPN, bytes, false);

        VpnPrefix vpn = (VpnPrefix) result.get(0);
        assertThat(vpn.mplsLabels()).containsExactly(0xFFFFFL);
        assertThat(vpn.rd().type()).isEqualTo(1);
        assertThat(vpn.rd().asText()).isEqualTo("1.1.1.1:5");
        assertThat(vpn.prefix().asCidr()).isEqualTo("10.0.0.0/8");
    }

    @Test
    void decodesL3VpnWithAddPath() {
        byte[] bytes = hex("00000007  70  000101  0000 0064 000000C8  0A0000");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_MPLS_VPN, bytes, true);

        assertThat(result).hasSize(1);
        AddPathNlri wrapped = (AddPathNlri) result.get(0);
        assertThat(wrapped.pathId()).isEqualTo(7L);
        VpnPrefix vpn = (VpnPrefix) wrapped.nlri();
        assertThat(vpn.mplsLabels()).containsExactly(16L);
        assertThat(vpn.prefix().asCidr()).isEqualTo("10.0.0.0/24");
    }

    @Test
    void decodesL3VpnMultiLabelStack() {
        // two labels: 16 (no BoS) then 17 (BoS). 16 no-BoS: 000100 ; 17 BoS: 000111
        // 17 -> ((0)<<12)|((0x01)<<4)|((0x11)>>4) = 16|1 = 17, BoS (0x11&0x01)=1
        // total bits = 48 (2 labels) + 64 (RD) + 24 (/24) = 136 -> 0x88
        byte[] bytes = hex("88  000100 000111  0000 0064 000000C8  0A0000");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_MPLS_VPN, bytes, false);

        VpnPrefix vpn = (VpnPrefix) result.get(0);
        assertThat(vpn.mplsLabels()).containsExactly(16L, 17L);
        assertThat(vpn.prefix().asCidr()).isEqualTo("10.0.0.0/24");
    }

    // ------------------------------------------------------------------
    // EVPN, AFI 25 / SAFI 70 (RFC 7432 §7)
    // ------------------------------------------------------------------

    @Test
    void decodesEvpnRoutes() {
        // route type 2 (MAC/IP), length 4, value AABBCCDD ; route type 3, length 2, value 1122
        byte[] bytes = hex("02 04 AABBCCDD   03 02 1122");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_L2VPN, AddressFamily.SAFI_EVPN, bytes, false);

        assertThat(result).hasSize(2);
        EvpnRoute r0 = (EvpnRoute) result.get(0);
        assertThat(r0.routeType()).isEqualTo(2);
        assertThat(r0.raw()).containsExactly(0xAA, 0xBB, 0xCC, 0xDD);
        assertThat(r0.afi()).isEqualTo(AddressFamily.AFI_L2VPN);
        assertThat(r0.safi()).isEqualTo(AddressFamily.SAFI_EVPN);
        EvpnRoute r1 = (EvpnRoute) result.get(1);
        assertThat(r1.routeType()).isEqualTo(3);
        assertThat(r1.raw()).containsExactly(0x11, 0x22);
    }

    @Test
    void decodesEvpnRouteDistinguisher() {
        // route type 1, length 8: RD type 0 asn 65000 num 1 = 0000 FDE8 00000001
        byte[] bytes = hex("01 08 0000 FDE8 00000001");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_L2VPN, AddressFamily.SAFI_EVPN, bytes, false);

        EvpnRoute route = (EvpnRoute) result.get(0);
        RouteDistinguisher rd = route.routeDistinguisher();
        assertThat(rd).isNotNull();
        assertThat(rd.type()).isEqualTo(0);
        assertThat(rd.asText()).isEqualTo("65000:1");
    }

    // ------------------------------------------------------------------
    // Flow Specification, SAFI 133/134 (RFC 8955)
    // ------------------------------------------------------------------

    @Test
    void decodesFlowSpecShortLengthEncoding() {
        // length < 0xF0: one rule, length 0x07.
        // component type 1 (dest prefix): 01 18 0A0000  (prefixLen 24, 3 octets)
        // component type 3 (IP protocol): 03 81 06  (op end-of-list len=1<<0=1, value 0x06=TCP)
        byte[] body = hex("01 18 0A0000  03 81 06");
        byte[] bytes = new byte[1 + body.length];
        bytes[0] = (byte) body.length; // 0x07
        System.arraycopy(body, 0, bytes, 1, body.length);

        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_FLOWSPEC, bytes, false);

        assertThat(result).hasSize(1);
        FlowSpecRule rule = (FlowSpecRule) result.get(0);
        assertThat(rule.safi()).isEqualTo(AddressFamily.SAFI_FLOWSPEC);
        assertThat(rule.components()).hasSize(2);
        FlowSpecComponent c0 = rule.components().get(0);
        assertThat(c0.type()).isEqualTo(1);
        assertThat(c0.raw()).containsExactly(0x18, 0x0A, 0x00, 0x00);
        FlowSpecComponent c1 = rule.components().get(1);
        assertThat(c1.type()).isEqualTo(3);
        assertThat(c1.raw()).containsExactly(0x81, 0x06);
        assertThat(rule.raw()).isEqualTo(body);
    }

    @Test
    void decodesFlowSpecLongLengthEncoding() {
        // Build a rule body of 0x100 (256) bytes so the 2-octet length form (>= 0xF0)
        // is exercised: length = ((b0 & 0x0F) << 8) | b1 = 0x100 -> b0=0xF1, b1=0x00.
        // The body is a single dest-prefix component (type 1) padded with more numeric
        // components is overkill; instead make one big component the decoder cannot fully
        // delimit and is preserved raw. We use type 1 prefix /24 then filler that the
        // numeric parser will consume/aggregate; to keep it deterministic we make the
        // whole 256-byte body a single type-1 prefix is impossible, so we assert the
        // rule length parsing and that zero bytes are lost.
        byte[] body = new byte[256];
        body[0] = 0x01;       // component type 1 (dest prefix)
        body[1] = 0x18;       // prefix length 24 -> 3 octets follow
        body[2] = 0x0A;
        body[3] = 0x00;
        body[4] = 0x00;
        // bytes [5..] are leftover; parser treats them as further components and, when it
        // cannot delimit, keeps them as one raw component. Either way no bytes are lost.
        byte[] bytes = new byte[2 + body.length];
        bytes[0] = (byte) 0xF1; // high nibble length bits = 1
        bytes[1] = 0x00;        // low byte = 0x00 -> total 0x100 = 256
        System.arraycopy(body, 0, bytes, 2, body.length);

        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_FLOWSPEC, bytes, false);

        assertThat(result).hasSize(1);
        FlowSpecRule rule = (FlowSpecRule) result.get(0);
        assertThat(rule.raw()).hasSize(256);
        assertThat(rule.raw()).isEqualTo(body);
        // First component must be the type-1 dest prefix.
        assertThat(rule.components().get(0).type()).isEqualTo(1);
        // Zero data loss: concatenating component bytes (with their type octets where
        // structured, raw where aggregated) accounts for the full body length.
        int accounted = 0;
        for (FlowSpecComponent c : rule.components()) {
            accounted += c.raw().length + (c.type() == 0xFF ? 0 : 1);
        }
        assertThat(accounted).isEqualTo(256);
    }

    @Test
    void decodesVpnFlowSpecWithRd() {
        // SAFI 134: leading 8-octet RD then components.
        // RD type 0 asn 100 num 1: 0000 0064 00000001
        // component type 1 dest prefix /24: 01 18 0A0000
        byte[] body = hex("0000 0064 00000001  01 18 0A0000");
        byte[] bytes = new byte[1 + body.length];
        bytes[0] = (byte) body.length;
        System.arraycopy(body, 0, bytes, 1, body.length);

        List<Nlri> result = NlriDecoder.decode(
                AddressFamily.AFI_IPV4, AddressFamily.SAFI_FLOWSPEC_VPN, bytes, false);

        FlowSpecRule rule = (FlowSpecRule) result.get(0);
        assertThat(rule.safi()).isEqualTo(AddressFamily.SAFI_FLOWSPEC_VPN);
        RouteDistinguisher rd = rule.routeDistinguisher();
        assertThat(rd).isNotNull();
        assertThat(rd.asText()).isEqualTo("100:1");
        // First synthetic component holds the RD bytes (type 0), then the dest prefix.
        assertThat(rule.components().get(0).type()).isEqualTo(0);
        assertThat(rule.components().get(0).raw()).hasSize(8);
        assertThat(rule.components().get(1).type()).isEqualTo(1);
    }

    // ------------------------------------------------------------------
    // SR Policy, SAFI 73
    // ------------------------------------------------------------------

    @Test
    void decodesSrPolicyAsRaw() {
        byte[] bytes = hex("60 00000001 00000064 01010101");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_SR_POLICY, bytes, false);

        assertThat(result).hasSize(1);
        SrPolicyNlri sr = (SrPolicyNlri) result.get(0);
        assertThat(sr.raw()).isEqualTo(bytes);
        assertThat(sr.safi()).isEqualTo(AddressFamily.SAFI_SR_POLICY);
    }

    // ------------------------------------------------------------------
    // BGP-LS, AFI 16388 / SAFI 71/72 (RFC 7752 §3.2)
    // ------------------------------------------------------------------

    @Test
    void decodesBgpLsNlri() {
        // nlriType 1 (Node), totalLength 4, value DEADBEEF ; nlriType 2 (Link), len 2, value CAFE
        byte[] bytes = hex("0001 0004 DEADBEEF   0002 0002 CAFE");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_BGP_LS, AddressFamily.SAFI_BGP_LS, bytes, false);

        assertThat(result).hasSize(2);
        LinkStateNlri n0 = (LinkStateNlri) result.get(0);
        assertThat(n0.nlriType()).isEqualTo(1);
        assertThat(n0.raw()).containsExactly(0xDE, 0xAD, 0xBE, 0xEF);
        assertThat(n0.afi()).isEqualTo(AddressFamily.AFI_BGP_LS);
        assertThat(n0.safi()).isEqualTo(AddressFamily.SAFI_BGP_LS);
        LinkStateNlri n1 = (LinkStateNlri) result.get(1);
        assertThat(n1.nlriType()).isEqualTo(2);
        assertThat(n1.raw()).containsExactly(0xCA, 0xFE);
    }

    @Test
    void decodesBgpLsVpnSafi() {
        byte[] bytes = hex("0003 0003 ABCDEF");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_BGP_LS, AddressFamily.SAFI_BGP_LS_VPN, bytes, false);
        assertThat(result).hasSize(1);
        assertThat(((LinkStateNlri) result.get(0)).nlriType()).isEqualTo(3);
    }

    // ------------------------------------------------------------------
    // Raw fallback for unknown families
    // ------------------------------------------------------------------

    @Test
    void unknownFamilyIsKeptRaw() {
        byte[] bytes = hex("DE AD BE EF");
        int unknownAfi = 9999;
        int unknownSafi = 200;
        List<Nlri> result = NlriDecoder.decode(unknownAfi, unknownSafi, bytes, false);

        assertThat(result).hasSize(1);
        RawNlri raw = (RawNlri) result.get(0);
        assertThat(raw.afi()).isEqualTo(unknownAfi);
        assertThat(raw.safi()).isEqualTo(unknownSafi);
        assertThat(raw.data()).isEqualTo(bytes);
    }

    @Test
    void emptyInputYieldsEmptyList() {
        assertThat(NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_UNICAST,
                new byte[0], false)).isEmpty();
        assertThat(NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_UNICAST,
                null, false)).isEmpty();
    }

    // ------------------------------------------------------------------
    // Negative / truncation: graceful raw capture (zero data loss)
    // ------------------------------------------------------------------

    @Test
    void truncatedIpv4PrefixIsCapturedRawNeverDropped() {
        // prefixLen 24 promises 3 octets but only 2 are present.
        byte[] bytes = hex("18 0A 00");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_UNICAST, bytes, false);

        assertThat(result).hasSize(1);
        RawNlri raw = (RawNlri) result.get(0);
        // Entire malformed element preserved verbatim.
        assertThat(raw.data()).isEqualTo(bytes);
        assertThat(raw.afi()).isEqualTo(AddressFamily.AFI_IPV4);
    }

    @Test
    void validPrefixThenTruncatedTailCapturesGoodPrefixAndRawTail() {
        // good 10.0.0.0/24 then a truncated /16 (only 1 octet present).
        byte[] bytes = hex("18 0A0000   10 C0");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_UNICAST, bytes, false);

        assertThat(result).hasSize(2);
        assertThat(((IpPrefix) result.get(0)).asCidr()).isEqualTo("10.0.0.0/24");
        RawNlri tail = (RawNlri) result.get(1);
        assertThat(tail.data()).containsExactly(0x10, 0xC0);
    }

    @Test
    void prefixLengthExceedingFamilyWidthIsCapturedRaw() {
        // /33 is impossible for IPv4.
        byte[] bytes = hex("21 0A000000 00");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_UNICAST, bytes, false);

        assertThat(result).hasSize(1);
        assertThat(result.get(0)).isInstanceOf(RawNlri.class);
        assertThat(((RawNlri) result.get(0)).data()).isEqualTo(bytes);
    }

    @Test
    void truncatedEvpnValueIsCapturedRaw() {
        // route type 2, length 8 but only 3 value octets present.
        byte[] bytes = hex("02 08 AABBCC");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_L2VPN, AddressFamily.SAFI_EVPN, bytes, false);

        assertThat(result).hasSize(1);
        assertThat(((RawNlri) result.get(0)).data()).isEqualTo(bytes);
    }

    @Test
    void truncatedBgpLsValueIsCapturedRaw() {
        // nlriType 1, totalLength 16 but only 2 octets present.
        byte[] bytes = hex("0001 0010 AABB");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_BGP_LS, AddressFamily.SAFI_BGP_LS, bytes, false);

        assertThat(result).hasSize(1);
        assertThat(((RawNlri) result.get(0)).data()).isEqualTo(bytes);
    }

    @Test
    void truncatedL3VpnBodyIsCapturedRaw() {
        // total bits 0x70 (=112 -> 14 bytes) but only the label + partial RD present.
        byte[] bytes = hex("70 000101 0000");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_MPLS_VPN, bytes, false);

        assertThat(result).hasSize(1);
        assertThat(((RawNlri) result.get(0)).data()).isEqualTo(bytes);
    }

    @Test
    void totalByteAccountingNeverLosesDataAcrossFamilies() {
        // A well-formed mixed unicast stream: verify total consumed equals input length
        // by reconstructing CIDR set; this guards against silent truncation.
        byte[] bytes = hex("18 0A0000  10 C0A8  08 0B");
        List<Nlri> result =
                NlriDecoder.decode(AddressFamily.AFI_IPV4, AddressFamily.SAFI_UNICAST, bytes, false);
        assertThat(result).extracting(n -> ((IpPrefix) n).asCidr())
                .containsExactly("10.0.0.0/24", "192.168.0.0/16", "11.0.0.0/8");
    }
}
