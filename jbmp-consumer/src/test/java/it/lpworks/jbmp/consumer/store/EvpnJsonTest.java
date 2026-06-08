package it.lpworks.jbmp.consumer.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link EvpnJson}, covering the structured rendering of the EVPN route
 * types (RFC 7432 §7, RFC 9136) and graceful degradation on truncated input.
 */
class EvpnJsonTest {

    @Test
    void nullInputYieldsNull() {
        assertThat(EvpnJson.toJson(2, null)).isNull();
    }

    @Test
    void emptyInputYieldsNull() {
        assertThat(EvpnJson.toJson(2, new byte[0])).isNull();
    }

    @Test
    void type2MacIpFullyDecoded() {
        // RD type 0 (admin=100, assigned=1) | ESI | EthernetTag=10 | MACLen=48 | MAC |
        // IPLen=32 | IP=10.0.0.1 | MPLS label1 (value 1).
        byte[] raw = {
                // RD (8): type 0, admin 100, assigned 1
                0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01,
                // ESI (10)
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99,
                // Ethernet Tag (4) = 10
                0x00, 0x00, 0x00, 0x0A,
                // MAC length in bits = 48
                0x30,
                // MAC (6)
                (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF,
                // IP length in bits = 32
                0x20,
                // IP (4) = 10.0.0.1
                0x0A, 0x00, 0x00, 0x01,
                // MPLS label1 (3) -> 0x000010 -> label value 1
                0x00, 0x00, 0x10
        };

        String json = EvpnJson.toJson(2, raw);

        assertThat(json).isEqualTo(
                "{\"route_type\":2,\"route_type_str\":\"mac_ip\",\"rd\":\"100:1\","
                + "\"esi\":\"00:11:22:33:44:55:66:77:88:99\",\"ethernet_tag\":10,"
                + "\"mac_len\":48,\"mac\":\"aa:bb:cc:dd:ee:ff\","
                + "\"ip_len\":32,\"ip\":\"10.0.0.1\",\"mpls_label1\":1}");
    }

    @Test
    void type3InclusiveMulticastWithIpv4OriginatingRouter() {
        // RD type 0 (admin=65000, assigned=5) | EthernetTag=0 | IPLen=32 | IP=192.0.2.1.
        byte[] raw = {
                // RD (8): type 0, admin 65000, assigned 5
                0x00, 0x00, (byte) 0xFD, (byte) 0xE8, 0x00, 0x00, 0x00, 0x05,
                // Ethernet Tag (4) = 0 (omitted from output)
                0x00, 0x00, 0x00, 0x00,
                // IP length in bits = 32
                0x20,
                // IP (4) = 192.0.2.1
                (byte) 0xC0, 0x00, 0x02, 0x01
        };

        String json = EvpnJson.toJson(3, raw);

        assertThat(json).isEqualTo(
                "{\"route_type\":3,\"route_type_str\":\"inclusive_multicast\","
                + "\"rd\":\"65000:5\",\"ip_len\":32,\"ip\":\"192.0.2.1\"}");
    }

    @Test
    void unknownRouteTypeStillEmitsRdAndMnemonic() {
        byte[] raw = {
                0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, // RD type 2, admin 65536, assigned 7
                0x01, 0x02, 0x03
        };

        String json = EvpnJson.toJson(9, raw);

        assertThat(json).isEqualTo(
                "{\"route_type\":9,\"route_type_str\":\"unknown_9\",\"rd\":\"65536:7\"}");
    }

    @Test
    void shortInputDegradesGracefullyWithoutThrowing() {
        // Only 3 bytes: too short for the 8-octet RD. Must not throw, and must keep data.
        byte[] raw = {0x01, 0x02, 0x03};

        assertThatCode(() -> EvpnJson.toJson(2, raw)).doesNotThrowAnyException();

        String json = EvpnJson.toJson(2, raw);
        assertThat(json)
                .startsWith("{\"route_type\":2,\"route_type_str\":\"mac_ip\",\"rd\":\"0:0\"")
                .endsWith("}");
        // The full input is preserved as the buffer is shorter than a complete route.
        assertThat(json).doesNotContain("\"mac\":");
    }

    @Test
    void type2TruncatedAfterEsiOmitsTrailingFields() {
        // RD (8) + ESI (10) only; everything after the ESI is missing.
        byte[] raw = new byte[18];
        // RD type 0, admin 1, assigned 2
        raw[3] = 0x01;
        raw[7] = 0x02;
        // ESI left as zeros -> 00:00:...:00

        String json = EvpnJson.toJson(2, raw);

        assertThat(json).isEqualTo(
                "{\"route_type\":2,\"route_type_str\":\"mac_ip\",\"rd\":\"1:2\","
                + "\"esi\":\"00:00:00:00:00:00:00:00:00:00\"}");
    }
}
