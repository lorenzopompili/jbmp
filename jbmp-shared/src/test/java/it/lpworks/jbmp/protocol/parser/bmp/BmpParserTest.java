package it.lpworks.jbmp.protocol.parser.bmp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import it.lpworks.jbmp.protocol.BmpParseException;
import it.lpworks.jbmp.protocol.bmp.BmpCommonHeader;
import it.lpworks.jbmp.protocol.bmp.BmpMessage;
import it.lpworks.jbmp.protocol.bmp.BmpMessageType;
import it.lpworks.jbmp.protocol.bmp.InitiationMessage;
import it.lpworks.jbmp.protocol.bmp.PeerDownNotification;
import it.lpworks.jbmp.protocol.bmp.PeerDownReason;
import it.lpworks.jbmp.protocol.bmp.PeerType;
import it.lpworks.jbmp.protocol.bmp.PeerUpNotification;
import it.lpworks.jbmp.protocol.bmp.PerPeerHeader;
import it.lpworks.jbmp.protocol.bmp.RouteMirroring;
import it.lpworks.jbmp.protocol.bmp.RouteMonitoring;
import it.lpworks.jbmp.protocol.bmp.StatisticsReport;
import it.lpworks.jbmp.protocol.bmp.TerminationMessage;
import it.lpworks.jbmp.protocol.bmp.stat.AdjRibInRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.PrefixesRejected;
import it.lpworks.jbmp.protocol.bmp.stat.StatCounter;
import it.lpworks.jbmp.protocol.bmp.stat.UnknownStat;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationType;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationType;
import it.lpworks.jbmp.protocol.io.ByteReader;
import it.lpworks.jbmp.protocol.parser.ParseMode;

import java.io.ByteArrayOutputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link BmpParser}.
 *
 * <p>Each test builds a hand-crafted BMP byte vector and asserts that the parser
 * decodes it into the expected model, or rejects malformed framing with a
 * {@link BmpParseException}. Vectors are assembled with the small {@link Builder}
 * helper, which fills in the 4-byte total-length field automatically.
 */
class BmpParserTest {

    private static final int VERSION = 3;

    // ------------------------------------------------------------------
    // Byte-vector helpers
    // ------------------------------------------------------------------

    /** Converts a (whitespace-tolerant) hex string into a {@code byte[]}. */
    private static byte[] hex(String s) {
        String clean = s.replaceAll("\\s", "");
        if (clean.length() % 2 != 0) {
            throw new IllegalArgumentException("Odd hex length: " + clean.length());
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Small append-only byte builder. */
    private static final class Bytes {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Bytes u8(int v) {
            out.write(v & 0xFF);
            return this;
        }

        Bytes u16(int v) {
            out.write((v >>> 8) & 0xFF);
            out.write(v & 0xFF);
            return this;
        }

        Bytes u32(long v) {
            out.write((int) ((v >>> 24) & 0xFF));
            out.write((int) ((v >>> 16) & 0xFF));
            out.write((int) ((v >>> 8) & 0xFF));
            out.write((int) (v & 0xFF));
            return this;
        }

        Bytes raw(byte[] b) {
            out.writeBytes(b);
            return this;
        }

        Bytes zeros(int n) {
            out.writeBytes(new byte[n]);
            return this;
        }

        byte[] toByteArray() {
            return out.toByteArray();
        }
    }

    /**
     * Wraps a body in a BMP common header, computing the total length automatically.
     *
     * @param type the message type code
     * @param body the message body bytes
     * @return the complete framed message
     */
    private static byte[] frame(int type, byte[] body) {
        long total = 6L + body.length;
        return new Bytes().u8(VERSION).u32(total).u8(type).raw(body).toByteArray();
    }

    /** Builds a 42-byte per-peer header with an IPv4 peer address (V flag clear). */
    private static byte[] perPeerHeaderIpv4(int flags, long asn, long tsSec, long tsMicros) {
        Bytes b = new Bytes();
        b.u8(0);                 // peer type 0 (global instance)
        b.u8(flags);             // peer flags
        b.zeros(8);              // distinguisher
        // 16-byte address field; IPv4 occupies the trailing 4 bytes -> 10.0.0.1
        b.zeros(12).u8(10).u8(0).u8(0).u8(1);
        b.u32(asn);              // peer ASN
        b.u8(192).u8(0).u8(2).u8(1); // BGP ID 192.0.2.1
        b.u32(tsSec);
        b.u32(tsMicros);
        return b.toByteArray();
    }

    /** Builds a minimal, well-formed raw BGP message (used as an OPEN frame). */
    private static byte[] bgpFrame(int totalLength, int bgpType) {
        Bytes b = new Bytes();
        for (int i = 0; i < 16; i++) {
            b.u8(0xFF);          // marker
        }
        b.u16(totalLength);      // length
        b.u8(bgpType);           // type
        b.zeros(totalLength - 19); // remaining body
        return b.toByteArray();
    }

    // ------------------------------------------------------------------
    // Common header
    // ------------------------------------------------------------------

    @Test
    void parseHeaderDecodesVersionLengthAndType() {
        byte[] msg = hex("03 00000006 04"); // version 3, length 6, type 4
        BmpCommonHeader h = BmpParser.parseHeader(new ByteReader(msg));
        assertThat(h.version()).isEqualTo(3);
        assertThat(h.messageLength()).isEqualTo(6L);
        assertThat(h.type()).isEqualTo(BmpMessageType.INITIATION);
    }

    @Test
    void shortHeaderThrows() {
        assertThatThrownBy(() -> BmpParser.parse(hex("03 0000"), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    @Test
    void badVersionThrows() {
        // version 2 instead of 3
        assertThatThrownBy(() -> BmpParser.parse(hex("02 00000006 04"), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class)
                .hasMessageContaining("version");
    }

    @Test
    void unknownMessageTypeThrows() {
        // type 7 is undefined
        assertThatThrownBy(() -> BmpParser.parse(hex("03 00000006 07"), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class)
                .hasMessageContaining("type");
    }

    @Test
    void lengthBelowHeaderMinimumThrows() {
        assertThatThrownBy(() -> BmpParser.parse(hex("03 00000005 04"), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    @Test
    void lengthOverflowBeyondBufferThrows() {
        // declares length 100 but only 6 bytes present
        assertThatThrownBy(() -> BmpParser.parse(hex("03 00000064 04"), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    // ------------------------------------------------------------------
    // Type 4: Initiation
    // ------------------------------------------------------------------

    @Test
    void parsesInitiationTlvs() {
        byte[] sysName = "r1".getBytes(StandardCharsets.UTF_8);
        byte[] body = new Bytes()
                .u16(2).u16(sysName.length).raw(sysName)   // SYS_NAME (type 2)
                .u16(99).u16(1).u8(0x41)                    // unknown type 99
                .toByteArray();
        byte[] msg = frame(4, body);

        BmpMessage m = BmpParser.parse(msg, ParseMode.STRICT);
        assertThat(m).isInstanceOf(InitiationMessage.class);
        InitiationMessage init = (InitiationMessage) m;
        assertThat(init.informationTlvs()).hasSize(2);

        InformationTlv first = init.informationTlvs().get(0);
        assertThat(first.type()).isEqualTo(InformationType.SYS_NAME);
        assertThat(first.asString()).isEqualTo("r1");

        InformationTlv second = init.informationTlvs().get(1);
        assertThat(second.type()).isEqualTo(InformationType.UNKNOWN);
        assertThat(second.rawType()).isEqualTo(99);
    }

    @Test
    void truncatedInitiationTlvThrows() {
        // declares a 5-byte value but supplies only 1
        byte[] body = new Bytes().u16(0).u16(5).u8(0x41).toByteArray();
        assertThatThrownBy(() -> BmpParser.parse(frame(4, body), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    // ------------------------------------------------------------------
    // Type 5: Termination
    // ------------------------------------------------------------------

    @Test
    void parsesTerminationReasonTlv() {
        byte[] body = new Bytes().u16(1).u16(2).u16(0).toByteArray(); // REASON code 0
        BmpMessage m = BmpParser.parse(frame(5, body), ParseMode.STRICT);
        assertThat(m).isInstanceOf(TerminationMessage.class);
        TerminationMessage term = (TerminationMessage) m;
        assertThat(term.tlvs()).hasSize(1);
        TerminationTlv tlv = term.tlvs().get(0);
        assertThat(tlv.type()).isEqualTo(TerminationType.REASON);
        assertThat(tlv.asReasonCode()).hasValue(0);
    }

    // ------------------------------------------------------------------
    // Type 1: Statistics Report
    // ------------------------------------------------------------------

    @Test
    void parsesStatisticsCounter32AndGauge64() {
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 65000L, 1_700_000_000L, 0L))
                .u32(3)                       // counter count
                .u16(0).u16(4).u32(42)        // PrefixesRejected = 42 (uint32)
                .u16(7).u16(8).u32(0).u32(99) // AdjRibInRoutes = 99 (uint64 gauge)
                .u16(250).u16(4).u32(7)       // unknown type 250 -> UnknownStat
                .toByteArray();
        byte[] msg = frame(1, body);

        BmpMessage m = BmpParser.parse(msg, ParseMode.STRICT);
        assertThat(m).isInstanceOf(StatisticsReport.class);
        StatisticsReport stats = (StatisticsReport) m;
        assertThat(stats.counters()).hasSize(3);

        StatCounter c0 = stats.counters().get(0);
        assertThat(c0).isInstanceOf(PrefixesRejected.class);
        assertThat(c0.value()).isEqualTo(42L);
        assertThat(c0.statType()).isEqualTo(0);

        StatCounter c1 = stats.counters().get(1);
        assertThat(c1).isInstanceOf(AdjRibInRoutes.class);
        assertThat(c1.value()).isEqualTo(99L);

        StatCounter c2 = stats.counters().get(2);
        assertThat(c2).isInstanceOf(UnknownStat.class);
        assertThat(c2.statType()).isEqualTo(250);
    }

    @Test
    void statisticsUnexpectedLengthBecomesUnknownStat() {
        // type 0 (PrefixesRejected) with a 2-byte value -> UnknownStat (unexpected width)
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .u32(1)
                .u16(0).u16(2).u16(5)
                .toByteArray();
        BmpMessage m = BmpParser.parse(frame(1, body), ParseMode.STRICT);
        StatisticsReport stats = (StatisticsReport) m;
        assertThat(stats.counters().get(0)).isInstanceOf(UnknownStat.class);
    }

    @Test
    void truncatedStatisticsCounterThrows() {
        // count says 1 but no counter bytes follow
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .u32(1)
                .toByteArray();
        assertThatThrownBy(() -> BmpParser.parse(frame(1, body), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    // ------------------------------------------------------------------
    // Per-peer header quirks
    // ------------------------------------------------------------------

    @Test
    void ipv4PeerAddressIsTrailingFourBytesOfField() {
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 65001L, 1_700_000_000L, 500L))
                .u32(0)
                .toByteArray();
        StatisticsReport stats = (StatisticsReport) BmpParser.parse(frame(1, body), ParseMode.STRICT);
        PerPeerHeader h = stats.peerHeader();
        assertThat(h.address()).isInstanceOf(Inet4Address.class);
        assertThat(h.address().getHostAddress()).isEqualTo("10.0.0.1");
        assertThat(h.peerType()).isEqualTo(PeerType.GLOBAL_INSTANCE);
        assertThat(h.peerAsn()).isEqualTo(65001L);
        assertThat(h.flags().ipv6()).isFalse();
        assertThat(h.bgpId().getHostAddress()).isEqualTo("192.0.2.1");
    }

    @Test
    void ipv6PeerAddressUsesFullSixteenByteField() {
        Bytes pph = new Bytes();
        pph.u8(0).u8(0x80);          // V flag set -> IPv6
        pph.zeros(8);                // distinguisher
        // 2001:db8::1
        pph.raw(hex("20010db8000000000000000000000001"));
        pph.u32(65002L);
        pph.u8(192).u8(0).u8(2).u8(9);
        pph.u32(1L).u32(0L);
        byte[] body = new Bytes().raw(pph.toByteArray()).u32(0).toByteArray();

        StatisticsReport stats = (StatisticsReport) BmpParser.parse(frame(1, body), ParseMode.STRICT);
        PerPeerHeader h = stats.peerHeader();
        assertThat(h.address()).isInstanceOf(Inet6Address.class);
        assertThat(h.flags().ipv6()).isTrue();
    }

    @Test
    void zeroTimestampFallsBackToNow() {
        Instant before = Instant.now();
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 0L, 0L)) // both timestamp fields zero
                .u32(0)
                .toByteArray();
        StatisticsReport stats = (StatisticsReport) BmpParser.parse(frame(1, body), ParseMode.STRICT);
        Instant after = Instant.now();
        assertThat(stats.peerHeader().timestamp())
                .isBetween(before.minusSeconds(1), after.plusSeconds(1));
    }

    @Test
    void nonZeroTimestampIsDecodedExactly() {
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1_700_000_000L, 250_000L))
                .u32(0)
                .toByteArray();
        StatisticsReport stats = (StatisticsReport) BmpParser.parse(frame(1, body), ParseMode.STRICT);
        assertThat(stats.peerHeader().timestamp())
                .isEqualTo(Instant.ofEpochSecond(1_700_000_000L, 250_000L * 1_000L));
    }

    @Test
    void unknownPeerTypeThrows() {
        Bytes pph = new Bytes();
        pph.u8(0x7F);                // unknown peer type
        pph.u8(0x00);
        pph.zeros(8);
        pph.zeros(12).u8(10).u8(0).u8(0).u8(1);
        pph.u32(1L);
        pph.u8(192).u8(0).u8(2).u8(1);
        pph.u32(1L).u32(0L);
        byte[] body = new Bytes().raw(pph.toByteArray()).u32(0).toByteArray();
        assertThatThrownBy(() -> BmpParser.parse(frame(1, body), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    @Test
    void truncatedPerPeerHeaderThrows() {
        // body too short for a 42-byte per-peer header
        byte[] body = new Bytes().zeros(10).toByteArray();
        assertThatThrownBy(() -> BmpParser.parse(frame(1, body), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    // ------------------------------------------------------------------
    // Type 2: Peer Down
    // ------------------------------------------------------------------

    @Test
    void parsesPeerDownNotificationReason1() {
        byte[] notification = bgpFrame(21, 3); // a tiny raw BGP NOTIFICATION
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .u8(1)               // reason 1: local notification
                .raw(notification)
                .toByteArray();
        BmpMessage m = BmpParser.parse(frame(2, body), ParseMode.STRICT);
        assertThat(m).isInstanceOf(PeerDownNotification.class);
        PeerDownNotification down = (PeerDownNotification) m;
        assertThat(down.reasonCode()).isEqualTo(1);
        assertThat(down.reason()).isEqualTo(PeerDownReason.LOCAL_NOTIFICATION);
        assertThat(down.data()).isEqualTo(notification);
    }

    @Test
    void parsesPeerDownReason2FsmCode() {
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .u8(2)               // reason 2: FSM event
                .u16(0x0006)         // 2-byte FSM code
                .toByteArray();
        PeerDownNotification down =
                (PeerDownNotification) BmpParser.parse(frame(2, body), ParseMode.STRICT);
        assertThat(down.reason()).isEqualTo(PeerDownReason.LOCAL_FSM);
        assertThat(down.data()).containsExactly(0x00, 0x06);
    }

    @Test
    void parsesPeerDownReason4Empty() {
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .u8(4)               // reason 4: remote, no notification
                .toByteArray();
        PeerDownNotification down =
                (PeerDownNotification) BmpParser.parse(frame(2, body), ParseMode.STRICT);
        assertThat(down.reason()).isEqualTo(PeerDownReason.REMOTE_NO_NOTIFICATION);
        assertThat(down.data()).isEmpty();
    }

    @Test
    void peerDownReason2TruncatedFsmThrows() {
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .u8(2).u8(0x00)      // only 1 of the 2 FSM bytes
                .toByteArray();
        assertThatThrownBy(() -> BmpParser.parse(frame(2, body), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    // ------------------------------------------------------------------
    // Type 3: Peer Up
    // ------------------------------------------------------------------

    @Test
    void parsesPeerUpNotification() {
        byte[] sentOpen = bgpFrame(29, 1);
        byte[] recvOpen = bgpFrame(31, 1);
        byte[] sysName = "peer".getBytes(StandardCharsets.UTF_8);

        Bytes body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 65010L, 1L, 0L))
                .zeros(12).u8(172).u8(16).u8(0).u8(5)   // local address 172.16.0.5 (IPv4 quirk)
                .u16(179)                                // local port
                .u16(50000)                              // remote port
                .raw(sentOpen)
                .raw(recvOpen)
                .u16(2).u16(sysName.length).raw(sysName); // trailing Information TLV

        PeerUpNotification up =
                (PeerUpNotification) BmpParser.parse(frame(3, body.toByteArray()), ParseMode.STRICT);
        assertThat(up.localAddress()).isInstanceOf(Inet4Address.class);
        assertThat(up.localAddress().getHostAddress()).isEqualTo("172.16.0.5");
        assertThat(up.localPort()).isEqualTo(179);
        assertThat(up.remotePort()).isEqualTo(50000);
        assertThat(up.sentOpenMessage()).isEqualTo(sentOpen);
        assertThat(up.receivedOpenMessage()).isEqualTo(recvOpen);
        assertThat(up.informationTlvs()).hasSize(1);
        assertThat(up.informationTlvs().get(0).asString()).isEqualTo("peer");
    }

    @Test
    void peerUpWithoutTrailingTlvs() {
        byte[] sentOpen = bgpFrame(19, 1);
        byte[] recvOpen = bgpFrame(19, 1);
        Bytes body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .zeros(12).u8(10).u8(0).u8(0).u8(9)
                .u16(179).u16(40000)
                .raw(sentOpen).raw(recvOpen);
        PeerUpNotification up =
                (PeerUpNotification) BmpParser.parse(frame(3, body.toByteArray()), ParseMode.STRICT);
        assertThat(up.informationTlvs()).isEmpty();
    }

    @Test
    void peerUpRejectsOpenLengthBelowMinimum() {
        // OPEN claims length 10 (< 19)
        byte[] badOpen = new Bytes().zeros(16).u16(10).u8(1).toByteArray();
        Bytes body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .zeros(16)
                .u16(179).u16(40000)
                .raw(badOpen);
        assertThatThrownBy(() -> BmpParser.parse(frame(3, body.toByteArray()), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    @Test
    void peerUpTruncatedOpenThrows() {
        // OPEN claims length 100 but only its 19-byte header is supplied
        byte[] badOpen = new Bytes().zeros(16).u16(100).u8(1).zeros(0).toByteArray();
        Bytes body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .zeros(16)
                .u16(179).u16(40000)
                .raw(badOpen);
        assertThatThrownBy(() -> BmpParser.parse(frame(3, body.toByteArray()), ParseMode.STRICT))
                .isInstanceOf(BmpParseException.class);
    }

    // ------------------------------------------------------------------
    // Type 6: Route Mirroring
    // ------------------------------------------------------------------

    @Test
    void parsesRouteMirroringBgpMessageAndInformationCode() {
        byte[] mirrored = bgpFrame(23, 2); // a mirrored BGP UPDATE
        Bytes body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .u16(0).u16(mirrored.length).raw(mirrored) // TLV type 0: BGP message
                .u16(1).u16(2).u16(1);                     // TLV type 1: info code 1

        RouteMirroring mir =
                (RouteMirroring) BmpParser.parse(frame(6, body.toByteArray()), ParseMode.STRICT);
        assertThat(mir.mirroredBgpMessage()).isEqualTo(mirrored);
        assertThat(mir.informationCode()).hasValue(1);
    }

    @Test
    void routeMirroringWithoutInformationCode() {
        byte[] mirrored = bgpFrame(23, 2);
        Bytes body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 1L, 1L, 0L))
                .u16(0).u16(mirrored.length).raw(mirrored);
        RouteMirroring mir =
                (RouteMirroring) BmpParser.parse(frame(6, body.toByteArray()), ParseMode.STRICT);
        assertThat(mir.informationCode()).isEmpty();
        assertThat(mir.mirroredBgpMessage()).isEqualTo(mirrored);
    }

    // ------------------------------------------------------------------
    // Type 0: Route Monitoring (delegates to the BGP layer)
    // ------------------------------------------------------------------

    @Test
    void parsesRouteMonitoringWithMinimalBgpUpdate() {
        // Minimal valid BGP UPDATE: marker(16x FF), length=23, type=2,
        // withdrawnLen=0, totalPathAttrLen=0, empty NLRI.
        byte[] bgpUpdate = new Bytes()
                .raw(hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")) // marker
                .u16(23)             // total length
                .u8(2)               // type UPDATE
                .u16(0)              // withdrawn routes length
                .u16(0)              // total path attribute length
                .toByteArray();
        byte[] body = new Bytes()
                .raw(perPeerHeaderIpv4(0x00, 65020L, 1L, 0L))
                .raw(bgpUpdate)
                .toByteArray();

        BmpMessage m = BmpParser.parse(frame(0, body), ParseMode.STRICT);
        assertThat(m).isInstanceOf(RouteMonitoring.class);
        RouteMonitoring rm = (RouteMonitoring) m;
        assertThat(rm.peerHeader().peerAsn()).isEqualTo(65020L);
        assertThat(rm.update().withdrawnRoutes()).isEmpty();
        assertThat(rm.update().nlri()).isEmpty();
        assertThat(rm.update().pathAttributes()).isEmpty();
    }

    // ------------------------------------------------------------------
    // Misc
    // ------------------------------------------------------------------

    @Test
    void byteArrayAndReaderEntryPointsAgree() {
        byte[] body = new Bytes().u16(0).u16(0).toByteArray(); // one empty STRING TLV
        byte[] msg = frame(4, body);
        BmpMessage viaArray = BmpParser.parse(msg, ParseMode.STRICT);
        BmpMessage viaReader = BmpParser.parse(new ByteReader(msg), ParseMode.STRICT);
        assertThat(viaArray).isEqualTo(viaReader);
    }
}
