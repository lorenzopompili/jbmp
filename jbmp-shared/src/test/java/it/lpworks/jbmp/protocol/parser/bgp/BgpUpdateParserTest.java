package it.lpworks.jbmp.protocol.parser.bgp;

import it.lpworks.jbmp.protocol.BmpParseException;
import it.lpworks.jbmp.protocol.bgp.Aggregator;
import it.lpworks.jbmp.protocol.bgp.AsPath;
import it.lpworks.jbmp.protocol.bgp.AsPathSegment;
import it.lpworks.jbmp.protocol.bgp.AsPathSegmentType;
import it.lpworks.jbmp.protocol.bgp.AtomicAggregate;
import it.lpworks.jbmp.protocol.bgp.ClusterList;
import it.lpworks.jbmp.protocol.bgp.Communities;
import it.lpworks.jbmp.protocol.bgp.ExtendedCommunities;
import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bgp.LargeCommunities;
import it.lpworks.jbmp.protocol.bgp.LargeCommunity;
import it.lpworks.jbmp.protocol.bgp.LocalPref;
import it.lpworks.jbmp.protocol.bgp.MpReachNlri;
import it.lpworks.jbmp.protocol.bgp.MpUnreachNlri;
import it.lpworks.jbmp.protocol.bgp.MultiExitDisc;
import it.lpworks.jbmp.protocol.bgp.NextHop;
import it.lpworks.jbmp.protocol.bgp.Origin;
import it.lpworks.jbmp.protocol.bgp.OriginType;
import it.lpworks.jbmp.protocol.bgp.OriginatorId;
import it.lpworks.jbmp.protocol.bgp.PathAttribute;
import it.lpworks.jbmp.protocol.bgp.UnknownAttribute;
import it.lpworks.jbmp.protocol.io.ByteReader;
import it.lpworks.jbmp.protocol.parser.ParseMode;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link BgpUpdateParser} and its package-private helpers.
 *
 * <p>Each test drives a hand-built BGP message byte vector (RFC 4271 §4.1 / §4.3) and
 * asserts the decoded {@link it.lpworks.jbmp.protocol.bgp.BgpUpdate}. Negative tests
 * assert {@link BmpParseException} in {@link ParseMode#STRICT} and graceful degradation
 * in {@link ParseMode#LENIENT}.
 */
class BgpUpdateParserTest {

    private static final HexFormat HEX = HexFormat.of();

    /** 16-octet all-ones BGP marker (RFC 4271 §4.1). */
    private static final String MARKER = "ffffffffffffffffffffffffffffffff";

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private static byte[] hex(String s) {
        return HEX.parseHex(s.replace(" ", "").replace("\n", ""));
    }

    private static ByteReader reader(byte[] bytes) {
        return new ByteReader(bytes);
    }

    /**
     * Wraps a body hex string into a complete BGP UPDATE message: prepends the marker,
     * computes and inserts the two-octet length and the type octet (2), then appends the
     * body.
     */
    private static byte[] update(String bodyHex) {
        byte[] body = hex(bodyHex);
        int total = 19 + body.length;
        byte[] msg = new byte[total];
        byte[] marker = hex(MARKER);
        System.arraycopy(marker, 0, msg, 0, 16);
        msg[16] = (byte) ((total >>> 8) & 0xFF);
        msg[17] = (byte) (total & 0xFF);
        msg[18] = 2; // UPDATE
        System.arraycopy(body, 0, msg, 19, body.length);
        return msg;
    }

    // ---------------------------------------------------------------------------
    // Full IPv4 UPDATE with many attributes
    // ---------------------------------------------------------------------------

    @Test
    void parsesFullIpv4UpdateWithManyAttributes() {
        // Withdrawn Routes Length = 0.
        // Path attributes:
        //   ORIGIN (flags 0x40, type 1, len 1, value 0=IGP)
        //   AS_PATH (flags 0x40, type 2, len 10):
        //       seg AS_SET(1) count 1 [65001]
        //       seg AS_SEQUENCE(2) count 2 [65002, 65003]
        //   NEXT_HOP (flags 0x40, type 3, len 4, 192.0.2.1)
        //   MED (flags 0x80, type 4, len 4, 100)
        //   LOCAL_PREF (flags 0x40, type 5, len 4, 300)
        //   COMMUNITIES (flags 0xC0, type 8, len 8, 65001:100, 65001:200)
        //   EXTENDED_COMMUNITIES (flags 0xC0, type 16, len 8, one RT)
        //   LARGE_COMMUNITIES (flags 0xC0, type 32, len 12, 65536:1:2)
        // NLRI: 24-bit prefix 198.51.100.0/24
        String origin = "40 01 01 00";
        String asPath = "40 02 0a 01 01 fde9 02 02 fdea fdeb";
        String nextHop = "40 03 04 c0000201";
        String med = "80 04 04 00000064";
        String localPref = "40 05 04 0000012c";
        String communities = "c0 08 08 fde90064 fde900c8";
        String extComm = "c0 10 08 0002fde9000000c8";
        String largeComm = "c0 20 0c 00010000 00000001 00000002";

        String attrs = origin + asPath + nextHop + med + localPref
                + communities + extComm + largeComm;
        int attrLen = hex(attrs).length;

        String body = "0000" // withdrawn length
                + String.format("%04x", attrLen)
                + attrs
                + "18 c63364"; // NLRI 198.51.100.0/24

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        assertThat(update.withdrawnRoutes()).isEmpty();

        assertThat(update.attribute(Origin.class)).contains(new Origin(OriginType.IGP));

        AsPath path = update.attribute(AsPath.class).orElseThrow();
        assertThat(path.segments()).hasSize(2);
        assertThat(path.segments().get(0).type()).isEqualTo(AsPathSegmentType.AS_SET);
        assertThat(path.segments().get(0).asns()).containsExactly(65001L);
        assertThat(path.segments().get(1).type()).isEqualTo(AsPathSegmentType.AS_SEQUENCE);
        assertThat(path.segments().get(1).asns()).containsExactly(65002L, 65003L);

        NextHop nh = update.attribute(NextHop.class).orElseThrow();
        assertThat(nh.address().getHostAddress()).isEqualTo("192.0.2.1");

        assertThat(update.attribute(MultiExitDisc.class)).contains(new MultiExitDisc(100));
        assertThat(update.attribute(LocalPref.class)).contains(new LocalPref(300));

        Communities comm = update.attribute(Communities.class).orElseThrow();
        assertThat(comm.values()).containsExactly(0xfde90064, 0xfde900c8);

        ExtendedCommunities ext = update.attribute(ExtendedCommunities.class).orElseThrow();
        assertThat(ext.communities()).hasSize(1);
        assertThat(ext.communities().get(0).isRouteTarget()).isTrue();

        LargeCommunities large = update.attribute(LargeCommunities.class).orElseThrow();
        assertThat(large.communities())
                .containsExactly(new LargeCommunity(65536L, 1L, 2L));

        assertThat(update.nlri()).hasSize(1);
        assertThat(update.nlri().get(0).asCidr()).isEqualTo("198.51.100.0/24");
    }

    // ---------------------------------------------------------------------------
    // Extended-length attribute
    // ---------------------------------------------------------------------------

    @Test
    void parsesExtendedLengthAttribute() {
        // ORIGIN with the extended-length flag set (0x50): 2-octet length 0x0001.
        String origin = "50 01 0001 02"; // value 2 = INCOMPLETE
        int attrLen = hex(origin).length;
        String body = "0000" + String.format("%04x", attrLen) + origin;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        assertThat(update.attribute(Origin.class))
                .contains(new Origin(OriginType.INCOMPLETE));
    }

    // ---------------------------------------------------------------------------
    // 2-byte vs 4-byte AS_PATH
    // ---------------------------------------------------------------------------

    @Test
    void parsesAsPathWithTwoByteAsns() {
        // AS_PATH AS_SEQUENCE of [65001, 65002] in 2-octet encoding.
        String asPath = "40 02 06 02 02 fde9 fdea";
        int attrLen = hex(asPath).length;
        String body = "0000" + String.format("%04x", attrLen) + asPath;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        AsPath path = update.attribute(AsPath.class).orElseThrow();
        assertThat(path.segments()).hasSize(1);
        assertThat(path.segments().get(0).asns()).containsExactly(65001L, 65002L);
    }

    @Test
    void parsesAsPathWithFourByteAsns() {
        // AS_PATH AS_SEQUENCE of [4200000000, 65002] in 4-octet encoding (asPath2Byte=false).
        String asPath = "40 02 0a 02 02 fa56ea00 0000fdea";
        int attrLen = hex(asPath).length;
        String body = "0000" + String.format("%04x", attrLen) + asPath;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, false);

        AsPath path = update.attribute(AsPath.class).orElseThrow();
        assertThat(path.segments().get(0).asns()).containsExactly(4200000000L, 65002L);
    }

    // ---------------------------------------------------------------------------
    // AS4_PATH merge (RFC 6793)
    // ---------------------------------------------------------------------------

    @Test
    void mergesAs4PathReplacingAsTransPlaceholders() {
        // AS_PATH (2-octet): AS_SEQUENCE [65001, 23456, 23456]  (two AS_TRANS placeholders)
        // AS4_PATH (4-octet): AS_SEQUENCE [4200000000, 4200000001]
        // Expected merge: leading 1 hop from AS_PATH (65001), then the AS4_PATH tail.
        String asPath = "40 02 08 02 03 fde9 5ba0 5ba0";
        String as4Path = "c0 11 0a 02 02 fa56ea00 fa56ea01";
        String attrs = asPath + as4Path;
        int attrLen = hex(attrs).length;
        String body = "0000" + String.format("%04x", attrLen) + attrs;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        AsPath path = update.attribute(AsPath.class).orElseThrow();
        // Single merged AS_PATH; no separate AS4_PATH attribute is emitted.
        assertThat(update.pathAttributes()).hasSize(1);
        assertThat(path.segments()).hasSize(2);
        assertThat(path.segments().get(0).asns()).containsExactly(65001L);
        assertThat(path.segments().get(1).asns()).containsExactly(4200000000L, 4200000001L);
    }

    @Test
    void as4PathLongerThanAsPathLeavesAsPathUnchanged() {
        // AS_PATH (2-octet): [65001]  (1 hop)
        // AS4_PATH (4-octet): [4200000000, 4200000001]  (2 hops, longer) -> ignored.
        String asPath = "40 02 04 02 01 fde9";
        String as4Path = "c0 11 0a 02 02 fa56ea00 fa56ea01";
        String attrs = asPath + as4Path;
        int attrLen = hex(attrs).length;
        String body = "0000" + String.format("%04x", attrLen) + attrs;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        AsPath path = update.attribute(AsPath.class).orElseThrow();
        assertThat(path.segments()).hasSize(1);
        assertThat(path.segments().get(0).asns()).containsExactly(65001L);
    }

    @Test
    void as4PathUnit_mergeReplacesTailAcrossSegmentBoundary() {
        // Direct unit test of AsPathParser.merge with mixed segment shapes.
        AsPath asPath = new AsPath(List.of(
                new AsPathSegment(AsPathSegmentType.AS_SEQUENCE,
                        new long[]{100L, 23456L, 23456L, 23456L})));
        AsPath as4Path = new AsPath(List.of(
                new AsPathSegment(AsPathSegmentType.AS_SEQUENCE,
                        new long[]{4200000000L, 4200000001L})));

        AsPath merged = AsPathParser.merge(asPath, as4Path);

        // 4 hops in AS_PATH, 2 in AS4_PATH -> keep 2 leading from AS_PATH, append AS4.
        assertThat(merged.segments()).hasSize(2);
        assertThat(merged.segments().get(0).asns()).containsExactly(100L, 23456L);
        assertThat(merged.segments().get(1).asns())
                .containsExactly(4200000000L, 4200000001L);
    }

    // ---------------------------------------------------------------------------
    // AGGREGATOR 6 vs 8 bytes, AS4_AGGREGATOR merge
    // ---------------------------------------------------------------------------

    @Test
    void parsesAggregatorWithTwoByteAs() {
        // AGGREGATOR len 6: 2-octet AS 65001 + 192.0.2.1.
        String agg = "c0 07 06 fde9 c0000201";
        int attrLen = hex(agg).length;
        String body = "0000" + String.format("%04x", attrLen) + agg;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        Aggregator a = update.attribute(Aggregator.class).orElseThrow();
        assertThat(a.asn()).isEqualTo(65001L);
        assertThat(a.address().getHostAddress()).isEqualTo("192.0.2.1");
    }

    @Test
    void parsesAggregatorWithFourByteAs() {
        // AGGREGATOR len 8: 4-octet AS 4200000000 + 192.0.2.1 (asPath2Byte=false).
        String agg = "c0 07 08 fa56ea00 c0000201";
        int attrLen = hex(agg).length;
        String body = "0000" + String.format("%04x", attrLen) + agg;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, false);

        Aggregator a = update.attribute(Aggregator.class).orElseThrow();
        assertThat(a.asn()).isEqualTo(4200000000L);
    }

    @Test
    void mergesAs4AggregatorWhenAggregatorIsAsTrans() {
        // AGGREGATOR len 6 with AS_TRANS (23456) + 192.0.2.1.
        // AS4_AGGREGATOR len 8 with 4200000000 + 198.51.100.1.
        String agg = "c0 07 06 5ba0 c0000201";
        String as4Agg = "c0 12 08 fa56ea00 c6336401";
        String attrs = agg + as4Agg;
        int attrLen = hex(attrs).length;
        String body = "0000" + String.format("%04x", attrLen) + attrs;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        // Only one AGGREGATOR surfaces (no AS4_AGGREGATOR attribute emitted).
        assertThat(update.pathAttributes()).hasSize(1);
        Aggregator a = update.attribute(Aggregator.class).orElseThrow();
        assertThat(a.asn()).isEqualTo(4200000000L);
        assertThat(a.address().getHostAddress()).isEqualTo("198.51.100.1");
    }

    @Test
    void doesNotMergeAs4AggregatorWhenAggregatorIsRealAs() {
        // AGGREGATOR len 6 with a genuine 2-octet AS (65001) -> AS4_AGGREGATOR ignored.
        String agg = "c0 07 06 fde9 c0000201";
        String as4Agg = "c0 12 08 fa56ea00 c6336401";
        String attrs = agg + as4Agg;
        int attrLen = hex(attrs).length;
        String body = "0000" + String.format("%04x", attrLen) + attrs;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        Aggregator a = update.attribute(Aggregator.class).orElseThrow();
        assertThat(a.asn()).isEqualTo(65001L);
        assertThat(a.address().getHostAddress()).isEqualTo("192.0.2.1");
    }

    // ---------------------------------------------------------------------------
    // ATOMIC_AGGREGATE, ORIGINATOR_ID, CLUSTER_LIST
    // ---------------------------------------------------------------------------

    @Test
    void parsesAtomicAggregateOriginatorIdAndClusterList() {
        String atomic = "40 06 00";
        String origId = "80 09 04 c0000202"; // 192.0.2.2
        String clusterList = "80 0a 08 c0000203 c0000204"; // two cluster IDs
        String attrs = atomic + origId + clusterList;
        int attrLen = hex(attrs).length;
        String body = "0000" + String.format("%04x", attrLen) + attrs;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        assertThat(update.attribute(AtomicAggregate.class)).contains(new AtomicAggregate());
        OriginatorId oid = update.attribute(OriginatorId.class).orElseThrow();
        assertThat(oid.id().getHostAddress()).isEqualTo("192.0.2.2");
        ClusterList cl = update.attribute(ClusterList.class).orElseThrow();
        assertThat(cl.clusterIds()).hasSize(2);
        assertThat(cl.clusterIds().get(0).getHostAddress()).isEqualTo("192.0.2.3");
        assertThat(cl.clusterIds().get(1).getHostAddress()).isEqualTo("192.0.2.4");
    }

    // ---------------------------------------------------------------------------
    // Withdrawn routes
    // ---------------------------------------------------------------------------

    @Test
    void parsesWithdrawnRoutes() {
        // Two withdrawn prefixes: 10.0.0.0/8 (1 value byte) and 172.16.0.0/12 (2 value bytes).
        String withdrawn = "08 0a" + "0c ac10";
        int wLen = hex(withdrawn).length;
        String body = String.format("%04x", wLen) + withdrawn + "0000"; // no path attrs

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        assertThat(update.withdrawnRoutes()).hasSize(2);
        assertThat(update.withdrawnRoutes().get(0).asCidr()).isEqualTo("10.0.0.0/8");
        assertThat(update.withdrawnRoutes().get(1).asCidr()).isEqualTo("172.16.0.0/12");
        assertThat(update.pathAttributes()).isEmpty();
        assertThat(update.nlri()).isEmpty();
    }

    @Test
    void parsesDefaultRouteZeroLengthPrefix() {
        // NLRI with a /0 default route: prefix length 0, zero value bytes.
        String body = "0000" + "0000" + "00";

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        assertThat(update.nlri()).hasSize(1);
        assertThat(update.nlri().get(0).asCidr()).isEqualTo("0.0.0.0/0");
    }

    // ---------------------------------------------------------------------------
    // MP_REACH / MP_UNREACH raw capture
    // ---------------------------------------------------------------------------

    @Test
    void capturesMpReachNlriRawBytes() {
        // MP_REACH_NLRI: afi=2 (IPv6), safi=1, nhLen=16, nextHop(16), reserved(1), nlri(rest).
        String nextHop16 = "20010db8000000000000000000000001";
        String nlri = "40 20010db8aaaa"; // opaque raw NLRI bytes (not decoded here)
        String value = "0002" + "01" + "10" + nextHop16 + "00" + nlri;
        int vLen = hex(value).length;
        String attr = "80 0e " + String.format("%02x", vLen) + value;
        int attrLen = hex(attr).length;
        String body = "0000" + String.format("%04x", attrLen) + attr;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        MpReachNlri mp = update.attribute(MpReachNlri.class).orElseThrow();
        assertThat(mp.afi()).isEqualTo(2);
        assertThat(mp.safi()).isEqualTo(1);
        assertThat(mp.nextHop()).isEqualTo(hex(nextHop16));
        assertThat(mp.nlri()).isEqualTo(hex(nlri));
    }

    @Test
    void capturesMpUnreachNlriRawBytes() {
        // MP_UNREACH_NLRI: afi=2, safi=1, withdrawn NLRI raw bytes.
        String raw = "40 20010db8bbbb";
        String value = "0002" + "01" + raw;
        int vLen = hex(value).length;
        String attr = "80 0f " + String.format("%02x", vLen) + value;
        int attrLen = hex(attr).length;
        String body = "0000" + String.format("%04x", attrLen) + attr;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        MpUnreachNlri mp = update.attribute(MpUnreachNlri.class).orElseThrow();
        assertThat(mp.afi()).isEqualTo(2);
        assertThat(mp.safi()).isEqualTo(1);
        assertThat(mp.withdrawnNlri()).isEqualTo(hex(raw));
    }

    @Test
    void mpUnreachEmptyIsEndOfRib() {
        // MP_UNREACH with empty NLRI for (afi=2, safi=1) is an End-of-RIB marker.
        String value = "0002" + "01";
        int vLen = hex(value).length;
        String attr = "80 0f " + String.format("%02x", vLen) + value;
        int attrLen = hex(attr).length;
        String body = "0000" + String.format("%04x", attrLen) + attr;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        assertThat(update.isEndOfRib()).isTrue();
    }

    // ---------------------------------------------------------------------------
    // Unknown attribute
    // ---------------------------------------------------------------------------

    @Test
    void capturesUnknownAttribute() {
        // Type code 99 (unassigned in this model) -> UnknownAttribute with raw value.
        String attr = "c0 63 03 aabbcc";
        int attrLen = hex(attr).length;
        String body = "0000" + String.format("%04x", attrLen) + attr;

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);

        UnknownAttribute u = update.attribute(UnknownAttribute.class).orElseThrow();
        assertThat(u.typeCode()).isEqualTo(99);
        assertThat(u.flags().optional()).isTrue();
        assertThat(u.flags().transitive()).isTrue();
        assertThat(u.value()).isEqualTo(hex("aabbcc"));
    }

    // ---------------------------------------------------------------------------
    // Framing negatives (always fatal regardless of mode)
    // ---------------------------------------------------------------------------

    @Test
    void rejectsNonUpdateMessageType() {
        // Build a valid header but type 1 (OPEN), empty body.
        byte[] msg = new byte[19];
        System.arraycopy(hex(MARKER), 0, msg, 0, 16);
        msg[16] = 0x00;
        msg[17] = 0x13; // length 19
        msg[18] = 0x01; // OPEN

        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(msg), ParseMode.LENIENT, true))
                .isInstanceOf(BmpParseException.class)
                .hasMessageContaining("UPDATE");
    }

    @Test
    void rejectsTruncatedHeader() {
        byte[] msg = new byte[10]; // shorter than the 19-octet header
        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(msg), ParseMode.STRICT, true))
                .isInstanceOf(BmpParseException.class);
    }

    @Test
    void rejectsWithdrawnLengthOverrunningBody() {
        // Withdrawn length declares 10 but the body has fewer bytes.
        String body = "000a" + "00"; // withdrawn len 10, only 1 stray byte follows
        // Cannot use update() length auto-calc cleanly here: build minimal body.
        byte[] msg = update(body);
        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(msg), ParseMode.STRICT, true))
                .isInstanceOf(BmpParseException.class)
                .hasMessageContaining("Withdrawn Routes");
        // Framing error is fatal in LENIENT too.
        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(update(body)), ParseMode.LENIENT, true))
                .isInstanceOf(BmpParseException.class);
    }

    @Test
    void rejectsPathAttrLengthOverrunningBody() {
        String body = "0000" + "00ff" + "40 01 01 00"; // path attr len 255, far too long
        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true))
                .isInstanceOf(BmpParseException.class)
                .hasMessageContaining("Path Attributes");
    }

    // ---------------------------------------------------------------------------
    // Content negatives: STRICT throws, LENIENT degrades gracefully
    // ---------------------------------------------------------------------------

    @Test
    void truncatedAttributeValueStrictThrowsLenientDegrades() {
        // ORIGIN (valid) then NEXT_HOP declaring len 4 but only 2 value bytes present.
        String origin = "40 01 01 00";
        String badNextHop = "40 03 04 c000"; // declared 4, only 2 bytes
        String attrs = origin + badNextHop;
        int attrLen = hex(attrs).length;
        String body = "0000" + String.format("%04x", attrLen) + attrs;

        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true))
                .isInstanceOf(BmpParseException.class);

        // Lenient: keeps the ORIGIN decoded before the truncated NEXT_HOP.
        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.LENIENT, true);
        assertThat(update.attribute(Origin.class)).contains(new Origin(OriginType.IGP));
        assertThat(update.attribute(NextHop.class)).isEmpty();
    }

    @Test
    void badCommunitiesLengthStrictThrowsLenientDegrades() {
        // COMMUNITIES with a length (6) that is not a multiple of 4.
        String origin = "40 01 01 00";
        String badComm = "c0 08 06 fde90064 fde9"; // 6 bytes, not /4
        String attrs = origin + badComm;
        int attrLen = hex(attrs).length;
        String body = "0000" + String.format("%04x", attrLen) + attrs;

        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true))
                .isInstanceOf(BmpParseException.class);

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.LENIENT, true);
        assertThat(update.attribute(Origin.class)).contains(new Origin(OriginType.IGP));
        assertThat(update.attribute(Communities.class)).isEmpty();
    }

    @Test
    void malformedWithdrawnPrefixStrictThrowsLenientStops() {
        // Withdrawn prefix declares /40 (illegal for IPv4).
        String withdrawn = "28 0a000000"; // /40
        int wLen = hex(withdrawn).length;
        String body = String.format("%04x", wLen) + withdrawn + "0000";

        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true))
                .isInstanceOf(BmpParseException.class);

        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.LENIENT, true);
        assertThat(update.withdrawnRoutes()).isEmpty();
    }

    @Test
    void unknownOriginCodeStrictThrows() {
        // ORIGIN code 9 is not a valid origin type.
        String origin = "40 01 01 09";
        int attrLen = hex(origin).length;
        String body = "0000" + String.format("%04x", attrLen) + origin;

        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true))
                .isInstanceOf(BmpParseException.class)
                .hasMessageContaining("ORIGIN");
    }

    @Test
    void badAggregatorLengthStrictThrows() {
        // AGGREGATOR with an illegal length of 5.
        String agg = "c0 07 05 fde9 c00002";
        int attrLen = hex(agg).length;
        String body = "0000" + String.format("%04x", attrLen) + agg;

        assertThatThrownBy(() -> BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true))
                .isInstanceOf(BmpParseException.class)
                .hasMessageContaining("AGGREGATOR");
    }

    @Test
    void emptyUpdateIsEndOfRib() {
        // Withdrawn len 0, path attr len 0, no NLRI = IPv4-unicast End-of-RIB.
        String body = "0000" + "0000";
        var update = BgpUpdateParser.parse(reader(update(body)), ParseMode.STRICT, true);
        assertThat(update.isEndOfRib()).isTrue();
        assertThat(update.pathAttributes()).isEmpty();
    }
}
