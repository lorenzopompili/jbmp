package it.lpworks.jbmp.consumer.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.ByteArrayOutputStream;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link BgpLsJson}, verifying the structured JSON produced for a BGP-LS path
 * attribute value (RFC 7752) and graceful degradation on malformed input.
 */
class BgpLsJsonTest {

    /** Appends a {@code [type(2), length(2), value]} TLV to the buffer. */
    private static void tlv(ByteArrayOutputStream out, int type, byte[] value) {
        out.write((type >>> 8) & 0xFF);
        out.write(type & 0xFF);
        out.write((value.length >>> 8) & 0xFF);
        out.write(value.length & 0xFF);
        out.writeBytes(value);
    }

    @Test
    void decodesKnownTlvsIntoStructuredJson() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Autonomous System (512): 65000 as a JSON number.
        tlv(out, 512, new byte[] {0x00, 0x00, (byte) 0xFD, (byte) 0xE8});
        // OSPF Area ID (514): rendered as an IPv4 address.
        tlv(out, 514, new byte[] {0x00, 0x00, 0x00, 0x01});
        // Link Local/Remote Identifier (258): {"local":1,"remote":2}.
        tlv(out, 258, new byte[] {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02});
        // IP Reachability (265): prefix length 24 with three address octets 10.0.2.
        tlv(out, 265, new byte[] {24, 10, 0, 2});
        // Max Link Bandwidth (1089): IEEE 754 single-precision 1_000_000 -> "1000000".
        tlv(out, 1089, new byte[] {0x49, 0x74, 0x24, 0x00});
        // Unknown TLV type: value preserved as lower-case hex.
        tlv(out, 9999, new byte[] {(byte) 0xAB, (byte) 0xCD});

        String json = BgpLsJson.toJson(out.toByteArray());

        assertThat(json).isEqualTo(
                "{\"tlvs\":["
                + "{\"type\":512,\"type_str\":\"autonomous_system\",\"length\":4,\"value\":65000},"
                + "{\"type\":514,\"type_str\":\"ospf_area_id\",\"length\":4,\"value\":\"0.0.0.1\"},"
                + "{\"type\":258,\"type_str\":\"link_local_remote_id\",\"length\":8,"
                + "\"value\":{\"local\":1,\"remote\":2}},"
                + "{\"type\":265,\"type_str\":\"ip_reachability_info\",\"length\":4,"
                + "\"value\":\"a00:200::/24\"},"
                + "{\"type\":1089,\"type_str\":\"max_link_bandwidth\",\"length\":4,"
                + "\"value\":\"1000000\"},"
                + "{\"type\":9999,\"type_str\":\"unknown_9999\",\"length\":2,\"value\":\"abcd\"}"
                + "],\"raw_len\":50}");
    }

    @Test
    void rendersNodeNameAndIsisSystemId() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // Node Name (1026): UTF-8 text value, JSON-escaped.
        tlv(out, 1026, "rtr-\"core\"".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        // IGP Router ID (515): 6-octet IS-IS system identifier -> dotted hex.
        tlv(out, 515, new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x2a});

        String json = BgpLsJson.toJson(out.toByteArray());

        assertThat(json)
                .contains("\"type_str\":\"node_name\",\"length\":10,\"value\":\"rtr-\\\"core\\\"\"")
                .contains("\"type_str\":\"igp_router_id\",\"length\":6,\"value\":\"0000.0000.002a\"");
    }

    @Test
    void returnsNullForNullOrEmptyInput() {
        assertThat(BgpLsJson.toJson(null)).isNull();
        assertThat(BgpLsJson.toJson(new byte[0])).isNull();
    }

    @Test
    void emitsNullTlvsWhenNothingParses() {
        // Fewer than the 4-octet TLV header: no TLV can be parsed, but raw_len is preserved.
        String json = BgpLsJson.toJson(new byte[] {0x01, 0x02, 0x03});
        assertThat(json).isEqualTo("{\"tlvs\":null,\"raw_len\":3}");
    }

    @Test
    void degradesGracefullyOnTruncatedTlvValue() {
        // TLV header declares a 16-octet value but only 2 octets follow: the scan stops without
        // throwing, the already-parsed TLV(s) are kept, and raw_len reflects the input.
        byte[] raw = new byte[] {
                0x02, 0x00,             // type 512
                0x00, 0x04,             // length 4
                0x00, 0x00, 0x00, 0x07, // value 7
                0x01, 0x03,             // type 259
                0x00, 0x10,             // length 16 (overruns)
                0x0a, 0x00              // only 2 octets present
        };

        String[] result = new String[1];
        assertThatCode(() -> result[0] = BgpLsJson.toJson(raw)).doesNotThrowAnyException();
        assertThat(result[0]).isEqualTo(
                "{\"tlvs\":["
                + "{\"type\":512,\"type_str\":\"autonomous_system\",\"length\":4,\"value\":7}"
                + "],\"raw_len\":14}");
    }
}
