package it.lpworks.jbmp.consumer.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link FlowSpecJson}, verifying the structured-JSON rendering of Flow
 * Specification rule bodies (RFC 8955 / RFC 9117) and its graceful degradation on
 * truncated input.
 */
class FlowSpecJsonTest {

    @Test
    void nullOrEmptyInputYieldsNull() {
        assertThat(FlowSpecJson.toJson(null)).isNull();
        assertThat(FlowSpecJson.toJson(new byte[0])).isNull();
    }

    @Test
    void decodesPrefixAndNumericComponents() {
        // Destination Prefix 10.0.0.0/8: type 1, prefixLen 0x08, one address octet 0x0a.
        // IP Protocol == 6: type 3, operator 0x81 (end-of-list, 1-octet value), value 0x06.
        byte[] raw = {
                0x01, 0x08, 0x0a,
                0x03, (byte) 0x81, 0x06
        };

        String json = FlowSpecJson.toJson(raw);

        assertThat(json).isEqualTo(
                "{\"length\":6,\"components\":["
                + "{\"type\":1,\"type_str\":\"dst_prefix\",\"raw\":\"0a/8\"},"
                + "{\"type\":3,\"type_str\":\"ip_protocol\",\"raw\":\"038106\"}"
                + "]}");
    }

    @Test
    void decodesVpnVariantWithRouteDistinguisher() {
        // RD type 0 = 100:200, then Destination Prefix 192.168.0.0/16.
        byte[] raw = {
                0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, (byte) 0xc8, // RD 100:200
                0x01, 0x10, (byte) 0xc0, (byte) 0xa8                    // dst 192.168.0.0/16
        };

        String json = FlowSpecJson.toJson(raw, true);

        assertThat(json).isEqualTo(
                "{\"length\":12,\"components\":["
                + "{\"type\":1,\"type_str\":\"dst_prefix\",\"raw\":\"c0a8/16\"}"
                + "],\"rd\":\"100:200\"}");
    }

    @Test
    void rendersUnknownComponentType() {
        // Unknown type 200, then a single terminating operator (0x80) with a 1-octet value.
        byte[] raw = {(byte) 0xc8, (byte) 0x80, 0x2a};

        String json = FlowSpecJson.toJson(raw);

        assertThat(json).isEqualTo(
                "{\"length\":3,\"components\":["
                + "{\"type\":200,\"type_str\":\"unknown_200\",\"raw\":\"c8802a\"}"
                + "]}");
    }

    @Test
    void truncatedComponentDegradesGracefullyWithoutThrowing() {
        // A bare numeric type octet with no operator/value following it.
        byte[] raw = {0x03};

        assertThatCode(() -> FlowSpecJson.toJson(raw)).doesNotThrowAnyException();

        String json = FlowSpecJson.toJson(raw);
        assertThat(json).isEqualTo(
                "{\"length\":1,\"components\":["
                + "{\"type\":3,\"type_str\":\"ip_protocol\",\"raw\":\"03\"}"
                + "]}");
    }

    @Test
    void truncatedPrefixKeepsRemainingBytes() {
        // Destination Prefix claiming /16 (2 address octets) but only one octet present.
        byte[] raw = {0x01, 0x10, (byte) 0xc0};

        assertThatCode(() -> FlowSpecJson.toJson(raw)).doesNotThrowAnyException();

        String json = FlowSpecJson.toJson(raw);
        assertThat(json).isEqualTo(
                "{\"length\":3,\"components\":["
                + "{\"type\":1,\"type_str\":\"dst_prefix\",\"raw\":\"c0/16\"}"
                + "]}");
    }
}
