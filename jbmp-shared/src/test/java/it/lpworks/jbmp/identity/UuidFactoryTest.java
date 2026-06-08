package it.lpworks.jbmp.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;

import org.junit.jupiter.api.Test;

/**
 * Tests deterministic identity derivation in {@link UuidFactory}: same input yields an
 * equal UUID, different input yields a different UUID, and the RFC 4122 version/variant
 * bits are correct.
 */
class UuidFactoryTest {

    private static final byte[] ROUTER_IP = {(byte) 203, 0, 113, 1};
    private static final byte[] PEER_IP = {(byte) 198, 51, 100, 7};

    @Test
    void routerIsDeterministic() {
        UUID a = UuidFactory.router(ROUTER_IP);
        UUID b = UuidFactory.router(ROUTER_IP.clone());
        assertThat(a).isEqualTo(b);
    }

    @Test
    void routerDiffersForDifferentInput() {
        assertThat(UuidFactory.router(ROUTER_IP))
                .isNotEqualTo(UuidFactory.router(new byte[]{(byte) 203, 0, 113, 2}));
    }

    @Test
    void routerHasVersion5AndRfc4122Variant() {
        assertVersionAndVariant(UuidFactory.router(ROUTER_IP));
        // IPv6 router address also yields valid bits.
        byte[] ipv6 = new byte[16];
        ipv6[0] = 0x20;
        ipv6[1] = 0x01;
        assertVersionAndVariant(UuidFactory.router(ipv6));
    }

    @Test
    void peerIsDeterministic() {
        UUID router = UuidFactory.router(ROUTER_IP);
        UUID a = UuidFactory.peer(router, PEER_IP, 65001, "65000:1");
        UUID b = UuidFactory.peer(router, PEER_IP.clone(), 65001, "65000:1");
        assertThat(a).isEqualTo(b);
    }

    @Test
    void peerHasVersion5AndRfc4122Variant() {
        UUID router = UuidFactory.router(ROUTER_IP);
        assertVersionAndVariant(UuidFactory.peer(router, PEER_IP, 65001, ""));
    }

    @Test
    void peerDiffersWhenAnyInputDiffers() {
        UUID router = UuidFactory.router(ROUTER_IP);
        UUID other = UuidFactory.router(new byte[]{1, 1, 1, 1});
        UUID base = UuidFactory.peer(router, PEER_IP, 65001, "65000:1");

        assertThat(base).isNotEqualTo(UuidFactory.peer(other, PEER_IP, 65001, "65000:1"));
        assertThat(base).isNotEqualTo(
                UuidFactory.peer(router, new byte[]{1, 2, 3, 4}, 65001, "65000:1"));
        assertThat(base).isNotEqualTo(UuidFactory.peer(router, PEER_IP, 65002, "65000:1"));
        assertThat(base).isNotEqualTo(UuidFactory.peer(router, PEER_IP, 65001, "65000:2"));
    }

    @Test
    void peerEmptyVersusNonEmptyRdDiffer() {
        UUID router = UuidFactory.router(ROUTER_IP);
        assertThat(UuidFactory.peer(router, PEER_IP, 65001, ""))
                .isNotEqualTo(UuidFactory.peer(router, PEER_IP, 65001, "0:0"));
    }

    @Test
    void rejectsNullArguments() {
        assertThatThrownBy(() -> UuidFactory.router(null))
                .isInstanceOf(NullPointerException.class);
        UUID router = UuidFactory.router(ROUTER_IP);
        assertThatThrownBy(() -> UuidFactory.peer(null, PEER_IP, 1, ""))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> UuidFactory.peer(router, null, 1, ""))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> UuidFactory.peer(router, PEER_IP, 1, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void rejectsOutOfRangeAsn() {
        UUID router = UuidFactory.router(ROUTER_IP);
        assertThatThrownBy(() -> UuidFactory.peer(router, PEER_IP, -1, ""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> UuidFactory.peer(router, PEER_IP, 0x1_0000_0000L, ""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static void assertVersionAndVariant(UUID uuid) {
        assertThat(uuid.version()).isEqualTo(5);
        // java.util.UUID.variant() returns 2 for the RFC 4122 (Leach-Salz) variant.
        assertThat(uuid.variant()).isEqualTo(2);
    }
}
