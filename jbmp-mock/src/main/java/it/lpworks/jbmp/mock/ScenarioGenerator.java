package it.lpworks.jbmp.mock;

import it.lpworks.jbmp.protocol.bgp.IpPrefix;
import it.lpworks.jbmp.protocol.bmp.PeerFlags;
import it.lpworks.jbmp.protocol.bmp.PeerType;
import it.lpworks.jbmp.protocol.bmp.PerPeerHeader;
import it.lpworks.jbmp.protocol.bmp.stat.AdjRibInRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.DuplicatePrefixAdvertisements;
import it.lpworks.jbmp.protocol.bmp.stat.LocRibRoutes;
import it.lpworks.jbmp.protocol.bmp.stat.PrefixesRejected;
import it.lpworks.jbmp.protocol.bmp.stat.StatCounter;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.InformationType;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationTlv;
import it.lpworks.jbmp.protocol.bmp.tlv.TerminationType;
import it.lpworks.jbmp.protocol.builder.BgpUpdateBuilder;
import it.lpworks.jbmp.protocol.builder.BmpMessageBuilder;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Produces an ordered stream of fully-framed BMP message byte arrays for a single
 * monitoring session, using only {@link BmpMessageBuilder} and {@link BgpUpdateBuilder}.
 *
 * <p>This class performs no I/O: it is a pure, deterministic generator so that the exact
 * byte stream can be unit-tested by parsing it back with the BMP parser. The emitted
 * sequence, per the configured {@link Scenario}, is:
 *
 * <ol>
 *   <li>one Initiation message (RFC 7854 §4.3) carrying sysName/sysDescr;</li>
 *   <li>for each peer, a Peer Up Notification (RFC 7854 §4.10) with framed BGP OPENs;</li>
 *   <li>for each peer, an initial table dump of {@code prefixesPerPeer} Route Monitoring
 *       announcements (RFC 7854 §4.6) followed by an End-of-RIB marker (RFC 4724 §2);</li>
 *   <li>for each peer, a Statistics Report (RFC 7854 §4.8);</li>
 *   <li>for an {@linkplain Scenario#hasIncrementalChurn() incremental} scenario, a round
 *       of announce/withdraw Route Monitoring updates;</li>
 *   <li>for a {@linkplain Scenario#hasTeardown() teardown} scenario, a Peer Down
 *       Notification per peer (RFC 7854 §4.9) and a Termination message (RFC 7854 §4.4).</li>
 * </ol>
 *
 * <p>Each Route Monitoring announcement carries a production-grade BGP attribute set,
 * assembled by the {@link AttributeMixer}: multi-segment AS_PATHs (RFC 4271 §5.1.2,
 * RFC 5065), ORIGIN, MED, LOCAL_PREF and NEXT_HOP, an occasional ATOMIC_AGGREGATE +
 * AGGREGATOR pair (RFC 4271 §5.1.6 / §5.1.7), a randomised mix of standard, large and
 * extended communities (RFC 1997, RFC 8092, RFC 4360) and route-reflector attributes on a
 * fraction (RFC 4456). In the {@linkplain Scenario#hasFullAttributeMix() full-mix}
 * ({@code stress}) scenario a deterministic fraction of announcements are multiprotocol
 * routes — L3VPN (RFC 4364), EVPN (RFC 7432), Flow Specification (RFC 8955), SR Policy and
 * BGP-LS (RFC 7752) — carried in MP_REACH_NLRI attributes (RFC 4760), so every address
 * family appears in the stream.
 *
 * <p>All addresses and AS numbers are drawn from the documentation ranges of RFC 5737
 * (IPv4), RFC 3849 (IPv6) and RFC 5398 (AS numbers) so the generated traffic resembles a
 * real feed without referencing any real network. The attribute mix is a pure function of
 * the {@code (routerIndex, peerIndex, prefixIndex)} triple, so the exact byte stream stays
 * reproducible and unit-testable. Per-peer headers carry non-zero, microsecond-aligned
 * timestamps so they survive the parser's zero-timestamp fallback.
 */
public final class ScenarioGenerator {

    /** Documentation-range router/source address prefix base (RFC 5737 TEST-NET-1). */
    private static final int ROUTER_NET = 0xC0_00_02_00; // 192.0.2.0/24

    /** Documentation-range peer address base (RFC 5737 TEST-NET-2: 198.51.100.0/24). */
    private static final int PEER_NET = 0xC6_33_64_00;

    /** Documentation-range advertised-prefix base (RFC 5737 TEST-NET-3: 203.0.113.0). */
    private static final long ADVERTISED_NET_BASE = 0xCB_00_71_00L;

    /** First reserved-for-documentation 32-bit AS number (RFC 5398: 4200000000). */
    private static final long ASN_DOC_BASE = 4_200_000_000L;

    /** Local TCP port reported in Peer Up (the BGP port, RFC 4271 §3). */
    private static final int BGP_PORT = 179;

    /** A representative ephemeral remote TCP port reported in Peer Up. */
    private static final int REMOTE_PORT = 50_000;

    /** Length of the per-prefix announced block; /24 networks step by 256 addresses. */
    private static final int PREFIX_STEP = 256;

    /** Advertised prefix length, in bits. */
    private static final int PREFIX_LENGTH = 24;

    /** A fixed, microsecond-aligned, in-uint32-range base timestamp for all headers. */
    private static final Instant BASE_TIMESTAMP =
            Instant.ofEpochSecond(1_700_000_000L, 500_000_000L);

    /** Peer Down reason 2: the local system closed the session via an FSM event. */
    private static final int PEER_DOWN_FSM = 2;

    /** The 2-octet BGP FSM event code payload carried by a reason-2 Peer Down. */
    private static final byte[] FSM_EVENT_CEASE = {0x00, 0x06};

    private final MockProperties properties;

    /** Assembles the full BGP attribute mix carried by each announcement. */
    private final AttributeMixer mixer;

    /**
     * Creates a generator bound to the given configuration.
     *
     * @param properties the mock configuration (router/peer/prefix counts, scenario)
     * @throws NullPointerException if {@code properties} is {@code null}
     */
    public ScenarioGenerator(MockProperties properties) {
        this.properties = Objects.requireNonNull(properties, "properties");
        this.mixer = new AttributeMixer(properties.resolvedScenario().hasFullAttributeMix());
    }

    /**
     * Generates the full message stream for one router session as a lazy {@link Stream}.
     *
     * @param routerIndex the zero-based router index (selects the router source address,
     *                    AS numbers and peer addresses); must be non-negative
     * @return a lazily evaluated stream of fully-framed BMP message bytes, in send order
     * @throws IllegalArgumentException if {@code routerIndex} is negative
     */
    public Stream<byte[]> generate(int routerIndex) {
        if (routerIndex < 0) {
            throw new IllegalArgumentException("routerIndex must be non-negative: " + routerIndex);
        }
        Iterator<byte[]> iterator = new SessionIterator(routerIndex);
        Spliterator<byte[]> spliterator = Spliterators.spliteratorUnknownSize(
                iterator, Spliterator.ORDERED | Spliterator.NONNULL);
        return StreamSupport.stream(spliterator, false);
    }

    /**
     * Generates the full message stream for one router session as a list. The whole
     * sequence is materialised, which is convenient for tests and small dumps.
     *
     * @param routerIndex the zero-based router index; must be non-negative
     * @return the complete ordered list of fully-framed BMP message bytes
     * @throws IllegalArgumentException if {@code routerIndex} is negative
     */
    public List<byte[]> generateAll(int routerIndex) {
        if (routerIndex < 0) {
            throw new IllegalArgumentException("routerIndex must be non-negative: " + routerIndex);
        }
        List<byte[]> out = new ArrayList<>();
        Iterator<byte[]> it = new SessionIterator(routerIndex);
        while (it.hasNext()) {
            out.add(it.next());
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Message construction
    // ------------------------------------------------------------------

    /**
     * Builds the session-opening Initiation message (RFC 7854 §4.3).
     *
     * @param routerIndex the router index, used to derive a distinct sysName
     * @return the encoded Initiation message
     */
    private byte[] initiation(int routerIndex) {
        List<InformationTlv> tlvs = List.of(
                tlv(InformationType.SYS_NAME, "jbmp-mock-router-" + routerIndex),
                tlv(InformationType.SYS_DESCR, "jBMP mock BMP source (RFC 7854)"));
        return BmpMessageBuilder.initiation(tlvs);
    }

    /**
     * Builds a Peer Up Notification (RFC 7854 §4.10) for one peer.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @return the encoded Peer Up Notification
     */
    private byte[] peerUp(int routerIndex, int peerIndex) {
        PerPeerHeader peer = peerHeader(routerIndex, peerIndex);
        byte[] open = bgpOpen(peerAsn(routerIndex, peerIndex));
        return BmpMessageBuilder.peerUp(
                peer, routerAddress(routerIndex), BGP_PORT, REMOTE_PORT, open, open, List.of());
    }

    /**
     * Builds one Route Monitoring announcement (RFC 7854 §4.6) for the given prefix.
     *
     * <p>The attribute set is assembled by the {@link AttributeMixer}: a richly-attributed
     * IPv4-unicast route in every scenario, and — in the {@linkplain Scenario#STRESS full
     * attribute mix} — an occasional multiprotocol route (L3VPN, EVPN, Flow Specification,
     * SR Policy or BGP-LS) whose reachability is carried inside an MP_REACH_NLRI attribute
     * (RFC 4760) rather than in the IPv4-unicast NLRI list. The {@code prefixIndex == 0}
     * route of every peer is pinned to a fixed, vanilla IPv4-unicast attribute set.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @param prefixIndex the zero-based prefix ordinal within the peer's dump
     * @return the encoded Route Monitoring message carrying an announce UPDATE
     */
    private byte[] announce(int routerIndex, int peerIndex, int prefixIndex) {
        PerPeerHeader peer = peerHeader(routerIndex, peerIndex);
        long originAsn = peerAsn(routerIndex, peerIndex);
        AttributeMixer.Announcement announcement =
                mixer.build(routerIndex, peerIndex, prefixIndex, originAsn, prefix(prefixIndex));
        byte[] bgp = BgpUpdateBuilder.update(
                List.of(), announcement.attributes(), announcement.nlri(), false);
        return BmpMessageBuilder.routeMonitoring(peer, bgp);
    }

    /**
     * Builds one Route Monitoring withdrawal (RFC 7854 §4.6) for the given prefix.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @param prefixIndex the zero-based prefix ordinal to withdraw
     * @return the encoded Route Monitoring message carrying a withdraw UPDATE
     */
    private byte[] withdraw(int routerIndex, int peerIndex, int prefixIndex) {
        PerPeerHeader peer = peerHeader(routerIndex, peerIndex);
        byte[] bgp = BgpUpdateBuilder.update(List.of(prefix(prefixIndex)), List.of(), List.of(), false);
        return BmpMessageBuilder.routeMonitoring(peer, bgp);
    }

    /**
     * Builds an End-of-RIB marker (RFC 4724 §2): a Route Monitoring message wrapping an
     * empty IPv4-unicast UPDATE.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @return the encoded End-of-RIB Route Monitoring message
     */
    private byte[] endOfRib(int routerIndex, int peerIndex) {
        PerPeerHeader peer = peerHeader(routerIndex, peerIndex);
        byte[] bgp = BgpUpdateBuilder.update(List.of(), List.of(), List.of(), false);
        return BmpMessageBuilder.routeMonitoring(peer, bgp);
    }

    /**
     * Builds a Statistics Report (RFC 7854 §4.8) reflecting the peer's dump size.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @return the encoded Statistics Report message
     */
    private byte[] statisticsReport(int routerIndex, int peerIndex) {
        long dump = properties.prefixesPerPeer();
        List<StatCounter> counters = List.of(
                new PrefixesRejected(0L),
                new DuplicatePrefixAdvertisements(0L),
                new AdjRibInRoutes(dump),
                new LocRibRoutes(dump));
        return BmpMessageBuilder.statisticsReport(peerHeader(routerIndex, peerIndex), counters);
    }

    /**
     * Builds a Peer Down Notification (RFC 7854 §4.9) closing the peering session via a
     * local FSM event (reason 2).
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @return the encoded Peer Down Notification
     */
    private byte[] peerDown(int routerIndex, int peerIndex) {
        return BmpMessageBuilder.peerDown(
                peerHeader(routerIndex, peerIndex), PEER_DOWN_FSM, FSM_EVENT_CEASE);
    }

    /**
     * Builds the session-closing Termination message (RFC 7854 §4.4).
     *
     * @return the encoded Termination message
     */
    private byte[] termination() {
        List<TerminationTlv> tlvs = List.of(new TerminationTlv(
                TerminationType.STRING, TerminationType.STRING.code(),
                "session closed by jbmp-mock".getBytes(StandardCharsets.UTF_8)));
        return BmpMessageBuilder.termination(tlvs);
    }

    // ------------------------------------------------------------------
    // Field derivation
    // ------------------------------------------------------------------

    /**
     * Builds the per-peer header for one peer (RFC 7854 §4.2). The L flag is set
     * (post-policy Adj-RIB-In) and the A flag is clear (4-byte AS_PATH), matching the
     * 4-byte AS_PATH encoding used for every advertisement.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @return the per-peer header
     */
    private PerPeerHeader peerHeader(int routerIndex, int peerIndex) {
        return new PerPeerHeader(
                PeerType.GLOBAL_INSTANCE,
                new PeerFlags(false, true, false),
                new byte[8],
                peerAddress(routerIndex, peerIndex),
                peerAsn(routerIndex, peerIndex),
                routerAddress(routerIndex),
                BASE_TIMESTAMP.plusSeconds((long) routerIndex * 1000L + peerIndex));
    }

    /**
     * Derives a distinct router source address from the documentation range.
     *
     * @param routerIndex the router index
     * @return the router's IPv4 source address
     */
    private Inet4Address routerAddress(int routerIndex) {
        return v4FromInt(ROUTER_NET | (1 + (routerIndex % 254)));
    }

    /**
     * Derives a distinct peer address from the documentation range.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @return the peer's IPv4 address
     */
    private Inet4Address peerAddress(int routerIndex, int peerIndex) {
        int host = 1 + ((routerIndex * properties.peersPerRouter() + peerIndex) % 254);
        return v4FromInt(PEER_NET | host);
    }

    /**
     * Derives a distinct, documentation-range origin AS number for a peer.
     *
     * @param routerIndex the router index
     * @param peerIndex   the peer index within the router
     * @return the peer's origin ASN
     */
    private long peerAsn(int routerIndex, int peerIndex) {
        return ASN_DOC_BASE + (long) routerIndex * properties.peersPerRouter() + peerIndex;
    }

    /**
     * Builds the {@code prefixIndex}-th advertised /24 prefix from the documentation range.
     *
     * @param prefixIndex the zero-based prefix ordinal
     * @return the advertised prefix
     */
    private IpPrefix prefix(int prefixIndex) {
        long base = (ADVERTISED_NET_BASE + (long) prefixIndex * PREFIX_STEP) & 0xFFFF_FFFFL;
        return new IpPrefix(v4FromInt((int) base), PREFIX_LENGTH);
    }

    /**
     * Builds a minimal, self-framed BGP OPEN message (RFC 4271 §4.2): a 19-octet header
     * followed by version, the 2-octet (or AS_TRANS) hold time / AS and an empty
     * optional-parameters block. The 4-byte ASN is conveyed via AS_TRANS (23456) in the
     * legacy 2-octet My AS field, which suffices because the parser retains the OPEN raw.
     *
     * @param asn the peer ASN advertised in the OPEN (carried as AS_TRANS when &gt;65535)
     * @return the raw OPEN message bytes
     */
    private static byte[] bgpOpen(long asn) {
        int myAs = asn > 0xFFFFL ? 23_456 : (int) asn; // AS_TRANS per RFC 6793 §4.1.
        int holdTime = 90;
        int bgpId = ROUTER_NET | 0x01;
        byte[] open = new byte[29];
        for (int i = 0; i < 16; i++) {
            open[i] = (byte) 0xFF; // Marker.
        }
        open[16] = 0x00;
        open[17] = 0x1D; // Length = 29.
        open[18] = 0x01; // Type = OPEN.
        open[19] = 0x04; // Version 4.
        open[20] = (byte) (myAs >>> 8);
        open[21] = (byte) myAs;
        open[22] = (byte) (holdTime >>> 8);
        open[23] = (byte) holdTime;
        open[24] = (byte) (bgpId >>> 24);
        open[25] = (byte) (bgpId >>> 16);
        open[26] = (byte) (bgpId >>> 8);
        open[27] = (byte) bgpId;
        open[28] = 0x00; // Optional Parameters Length = 0.
        return open;
    }

    private static InformationTlv tlv(InformationType type, String value) {
        return new InformationTlv(type, type.code(), value.getBytes(StandardCharsets.UTF_8));
    }

    private static Inet4Address v4FromInt(int value) {
        byte[] bytes = {
                (byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value};
        try {
            return (Inet4Address) InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Cannot build IPv4 address from " + value, e);
        }
    }

    // ------------------------------------------------------------------
    // Session iterator
    // ------------------------------------------------------------------

    /**
     * A lazy, single-pass iterator over the ordered message stream of one session.
     *
     * <p>Materialising the dump eagerly would defeat the point of a generator for large
     * {@code prefixesPerPeer} values, so messages are produced on demand by walking a
     * small state machine: preamble, per-peer dump and stats, optional churn, optional
     * teardown.
     */
    private final class SessionIterator implements Iterator<byte[]> {

        private final int routerIndex;
        private final int peers = properties.peersPerRouter();
        private final int prefixes = properties.prefixesPerPeer();
        private final Scenario scenario = properties.resolvedScenario();
        private final int churnCount = scenario.hasIncrementalChurn()
                ? Math.max(0, properties.incrementalUpdatesPerSecond())
                : 0;

        /** Pre-built, fixed-position tail (stats, churn, teardown) emitted after the dump. */
        private final Iterator<byte[]> tail;

        /** Cursor over the streaming preamble + dump phase. */
        private int phase;     // 0 = initiation, 1 = peer-ups, 2 = dump
        private int peerCursor;
        private int prefixCursor;
        private boolean initiationDone;

        SessionIterator(int routerIndex) {
            this.routerIndex = routerIndex;
            this.tail = buildTail().iterator();
        }

        @Override
        public boolean hasNext() {
            return !initiationDone
                    || peerCursor < peers
                    || tail.hasNext();
        }

        @Override
        public byte[] next() {
            // Phase 0: the single Initiation message.
            if (!initiationDone) {
                initiationDone = true;
                phase = peers > 0 ? 1 : 2;
                return initiation(routerIndex);
            }
            // Phase 1: one Peer Up per peer.
            if (phase == 1) {
                byte[] msg = peerUp(routerIndex, peerCursor);
                if (++peerCursor >= peers) {
                    peerCursor = 0;
                    phase = 2;
                }
                return msg;
            }
            // Phase 2: per-peer table dump, each peer terminated by an End-of-RIB marker.
            if (phase == 2 && peerCursor < peers) {
                if (prefixCursor < prefixes) {
                    return announce(routerIndex, peerCursor, prefixCursor++);
                }
                byte[] eor = endOfRib(routerIndex, peerCursor);
                prefixCursor = 0;
                peerCursor++;
                return eor;
            }
            // Phase 3: the fixed tail (stats, optional churn, optional teardown).
            return tail.next();
        }

        /**
         * Builds the fixed message tail emitted after the table dump: a Statistics Report
         * per peer, an optional round of incremental announce/withdraw churn, and an
         * optional graceful teardown.
         *
         * @return the ordered tail messages
         */
        private List<byte[]> buildTail() {
            List<byte[]> out = new ArrayList<>();
            for (int p = 0; p < peers; p++) {
                out.add(statisticsReport(routerIndex, p));
            }
            for (int i = 0; i < churnCount; i++) {
                int peer = peers == 0 ? 0 : i % peers;
                // Re-announce the next prefix slot, then withdraw an existing one, to
                // exercise both code paths on the collector.
                out.add(announce(routerIndex, peer, prefixes + i));
                out.add(withdraw(routerIndex, peer, i % Math.max(1, prefixes)));
            }
            if (scenario.hasTeardown()) {
                for (int p = 0; p < peers; p++) {
                    out.add(peerDown(routerIndex, p));
                }
                out.add(termination());
            }
            return out;
        }
    }
}
