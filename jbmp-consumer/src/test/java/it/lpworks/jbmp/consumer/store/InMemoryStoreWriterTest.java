package it.lpworks.jbmp.consumer.store;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import it.lpworks.jbmp.consumer.TestMessages;
import it.lpworks.jbmp.wire.RouteMonitorMessage;

/**
 * Unit tests for {@link InMemoryStoreWriter}, focusing on the idempotent routing-state
 * projection and the batch/record retention used by the other tests.
 */
class InMemoryStoreWriterTest {

    private static final UUID PEER = TestMessages.peer(1);

    private InMemoryStoreWriter store;

    @BeforeEach
    void setUp() {
        store = new InMemoryStoreWriter();
    }

    @Test
    void announceUpsertsAndWithdrawDeletes() {
        store.applyRibState(List.of(
                TestMessages.announce(PEER, 1),
                TestMessages.announce(PEER, 2)));
        assertThat(store.ribState()).hasSize(2);

        store.applyRibState(List.of(TestMessages.withdraw(PEER, 1)));
        assertThat(store.ribState()).hasSize(1);
        assertThat(store.ribState().keySet().iterator().next().prefix())
                .containsExactly(10, 0, 2, 0);
    }

    @Test
    void reapplyingTheSameBatchIsIdempotent() {
        List<RouteMonitorMessage> batch = List.of(
                TestMessages.announce(PEER, 1),
                TestMessages.announce(PEER, 2),
                TestMessages.withdraw(PEER, 1));

        store.applyRibState(batch);
        var firstState = store.ribState();

        store.applyRibState(batch); // re-delivery
        assertThat(store.ribState()).isEqualTo(firstState).hasSize(1);
    }

    @Test
    void endOfRibIsIgnoredByRibProjection() {
        store.applyRibState(List.of(
                TestMessages.announce(PEER, 1),
                TestMessages.endOfRib(PEER)));

        assertThat(store.ribState()).hasSize(1);
    }

    @Test
    void writeRouteMonitorBatchRetainsBatchesAndCountsRows() {
        store.writeRouteMonitorBatch(List.of(
                TestMessages.announce(PEER, 1),
                TestMessages.announce(PEER, 2)));
        store.writeRouteMonitorBatch(List.of(TestMessages.announce(PEER, 3)));

        assertThat(store.routeMonitorBatches()).hasSize(2);
        assertThat(store.routeMonitorRowCount()).isEqualTo(3);
        assertThat(store.allRouteMonitorMessages()).hasSize(3);
    }

    @Test
    void emptyRouteMonitorBatchIsANoOp() {
        store.writeRouteMonitorBatch(List.of());
        assertThat(store.routeMonitorBatches()).isEmpty();
        assertThat(store.routeMonitorRowCount()).isZero();
    }

    @Test
    void singleMessageWritersRetainRecords() {
        store.writePeerEvent(TestMessages.peerUp(PEER));
        store.writeStats(TestMessages.stats(PEER));
        store.writeRouteMirror(TestMessages.routeMirror(PEER));

        assertThat(store.peerEvents()).hasSize(1);
        assertThat(store.stats()).hasSize(1);
        assertThat(store.routeMirrors()).hasSize(1);
    }

    @Test
    void clearResetsEverything() {
        store.writeRouteMonitorBatch(List.of(TestMessages.announce(PEER, 1)));
        store.applyRibState(List.of(TestMessages.announce(PEER, 1)));
        store.writePeerEvent(TestMessages.peerUp(PEER));

        store.clear();

        assertThat(store.routeMonitorBatches()).isEmpty();
        assertThat(store.ribState()).isEmpty();
        assertThat(store.peerEvents()).isEmpty();
        assertThat(store.routeMonitorRowCount()).isZero();
    }
}
