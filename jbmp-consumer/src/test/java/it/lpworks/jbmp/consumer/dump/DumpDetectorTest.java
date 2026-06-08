package it.lpworks.jbmp.consumer.dump;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import it.lpworks.jbmp.consumer.TestMessages;

/**
 * Unit tests for {@link DumpDetector}: a peer enters the initial-dump state on its first
 * route-monitor message and leaves it on End-of-RIB, independently per peer.
 */
class DumpDetectorTest {

    private static final UUID PEER_A = TestMessages.peer(1);
    private static final UUID PEER_B = TestMessages.peer(2);

    private DumpDetector detector;

    @BeforeEach
    void setUp() {
        detector = new DumpDetector();
    }

    @Test
    void unknownPeerIsNotInDump() {
        assertThat(detector.isInDump(PEER_A)).isFalse();
        assertThat(detector.inDumpCount()).isZero();
    }

    @Test
    void firstRouteMonitorMarksPeerInDump() {
        boolean inDump = detector.observe(TestMessages.announce(PEER_A, 1));

        assertThat(inDump).isTrue();
        assertThat(detector.isInDump(PEER_A)).isTrue();
        assertThat(detector.inDumpCount()).isEqualTo(1);
    }

    @Test
    void endOfRibClearsDumpState() {
        detector.observe(TestMessages.announce(PEER_A, 1));
        detector.observe(TestMessages.announce(PEER_A, 2));
        assertThat(detector.isInDump(PEER_A)).isTrue();

        boolean stillInDump = detector.observe(TestMessages.endOfRib(PEER_A));

        assertThat(stillInDump).isFalse();
        assertThat(detector.isInDump(PEER_A)).isFalse();
        assertThat(detector.inDumpCount()).isZero();
    }

    @Test
    void dumpStateIsTrackedPerPeer() {
        detector.observe(TestMessages.announce(PEER_A, 1));
        detector.observe(TestMessages.announce(PEER_B, 1));
        assertThat(detector.inDumpCount()).isEqualTo(2);

        detector.observe(TestMessages.endOfRib(PEER_A)); // only A finishes

        assertThat(detector.isInDump(PEER_A)).isFalse();
        assertThat(detector.isInDump(PEER_B)).isTrue();
        assertThat(detector.inDumpCount()).isEqualTo(1);
    }

    @Test
    void postDumpTrafficReentersDumpStateUntilNextEndOfRib() {
        detector.observe(TestMessages.announce(PEER_A, 1));
        detector.observe(TestMessages.endOfRib(PEER_A));
        assertThat(detector.isInDump(PEER_A)).isFalse();

        // A later session re-dump (e.g. after a session bounce) re-arms the in-dump state.
        detector.observe(TestMessages.announce(PEER_A, 9));
        assertThat(detector.isInDump(PEER_A)).isTrue();
    }

    @Test
    void endOfRibForUntrackedPeerIsANoOp() {
        boolean inDump = detector.observe(TestMessages.endOfRib(PEER_A));

        assertThat(inDump).isFalse();
        assertThat(detector.isInDump(PEER_A)).isFalse();
        assertThat(detector.inDumpCount()).isZero();
    }

    @Test
    void resetForgetsAllPeers() {
        detector.observe(TestMessages.announce(PEER_A, 1));
        detector.observe(TestMessages.announce(PEER_B, 1));

        detector.reset();

        assertThat(detector.inDumpCount()).isZero();
        assertThat(detector.isInDump(PEER_A)).isFalse();
        assertThat(detector.isInDump(PEER_B)).isFalse();
    }

    @Test
    void rejectsNullArguments() {
        assertThatNullPointerException().isThrownBy(() -> detector.observe(null));
        assertThatNullPointerException().isThrownBy(() -> detector.isInDump(null));
    }
}
