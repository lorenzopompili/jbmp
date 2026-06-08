package it.lpworks.jbmp.consumer.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SrPolicyJson}, covering the structured-JSON encoding of BGP
 * SR Policy NLRI (SAFI 73, draft-ietf-idr-segment-routing-te-policy) and its graceful
 * degradation on malformed input.
 */
class SrPolicyJsonTest {

    @Test
    void decodesSingleIpv4PolicyWithBitLengthPrefix() {
        // bit-length prefix 0x60 (96 bits = 12 bytes) + distinguisher(1) + color(100)
        // + endpoint 192.0.2.1
        byte[] raw = {
                (byte) 0x60,                                     // length = 96 bits = 12 bytes
                0x00, 0x00, 0x00, 0x01,                          // distinguisher = 1
                0x00, 0x00, 0x00, 0x64,                          // color = 100
                (byte) 0xC0, 0x00, 0x02, 0x01                    // endpoint 192.0.2.1
        };

        String json = SrPolicyJson.toJson(raw);

        assertThat(json).isEqualTo(
                "[{\"distinguisher\":1,\"color\":100,"
                + "\"endpoint\":\"192.0.2.1\",\"endpoint_afi\":1}]");
    }

    @Test
    void decodesTwoIpv4Policies() {
        byte[] raw = {
                (byte) 0x60,                                     // 96 bits = 12 bytes
                0x00, 0x00, 0x00, 0x01,                          // distinguisher = 1
                0x00, 0x00, 0x00, 0x0A,                          // color = 10
                0x0A, 0x00, 0x00, 0x01,                          // endpoint 10.0.0.1
                (byte) 0x60,                                     // 96 bits = 12 bytes
                0x00, 0x00, 0x00, 0x02,                          // distinguisher = 2
                0x00, 0x00, 0x00, 0x14,                          // color = 20
                0x0A, 0x00, 0x00, 0x02                           // endpoint 10.0.0.2
        };

        String json = SrPolicyJson.toJson(raw);

        assertThat(json).isEqualTo(
                "[{\"distinguisher\":1,\"color\":10,\"endpoint\":\"10.0.0.1\",\"endpoint_afi\":1},"
                + "{\"distinguisher\":2,\"color\":20,\"endpoint\":\"10.0.0.2\",\"endpoint_afi\":1}]");
    }

    @Test
    void decodesIpv6PolicyWhenAfiIsSix() {
        // 192 bits = 24 bytes: distinguisher(4) + color(4) + 16-octet endpoint 2001:db8::1
        byte[] raw = {
                (byte) 0xC0,                                     // length = 192 bits
                0x00, 0x00, 0x00, 0x07,                          // distinguisher = 7
                0x00, 0x00, 0x00, 0x2A,                          // color = 42
                0x20, 0x01, 0x0D, (byte) 0xB8, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01   // endpoint 2001:db8::1
        };

        String json = SrPolicyJson.toJson(raw, 2);

        // java.net renders IPv6 fully expanded (no RFC 5952 compression).
        assertThat(json).isEqualTo(
                "[{\"distinguisher\":7,\"color\":42,"
                + "\"endpoint\":\"2001:db8:0:0:0:0:0:1\",\"endpoint_afi\":2}]");
    }

    @Test
    void nullAndEmptyInputReturnNull() {
        assertThat(SrPolicyJson.toJson(null)).isNull();
        assertThat(SrPolicyJson.toJson(new byte[0])).isNull();
    }

    @Test
    void shortBodyIsPreservedAsRawWithoutThrowing() {
        // Prefix says 32 bits (4 bytes) but a full IPv4 record needs 16 bytes:
        // the body is kept verbatim rather than dropped, and no exception escapes.
        byte[] raw = {
                0x20,                                            // length = 32 bits = 4 bytes
                0x00, 0x00, 0x00, 0x01
        };

        String json = assertThatNoThrow(raw);

        assertThat(json).isEqualTo("[{\"raw\":\"00000001\",\"len\":4}]");
    }

    @Test
    void overrunningPrefixIsCapturedAsRawRemainder() {
        // Prefix claims 128 bits but only 3 body bytes remain: the remainder (prefix byte
        // included) is preserved as one raw object and nothing throws.
        byte[] raw = {
                (byte) 0x80,
                (byte) 0xAA, (byte) 0xBB, (byte) 0xCC
        };

        String json = assertThatNoThrow(raw);

        assertThat(json).isEqualTo("[{\"raw\":\"80aabbcc\",\"len\":4}]");
    }

    @Test
    void wellFormedRecordAfterShortRecordIsStillDecoded() {
        byte[] raw = {
                0x20,                                            // short body: 32 bits = 4 bytes
                0x00, 0x00, 0x00, 0x09,
                (byte) 0x60,                                     // full IPv4 record: 96 bits = 12 bytes
                0x00, 0x00, 0x00, 0x03,                          // distinguisher = 3
                0x00, 0x00, 0x00, 0x05,                          // color = 5
                0x0A, 0x0B, 0x0C, 0x0D                           // endpoint 10.11.12.13
        };

        String json = SrPolicyJson.toJson(raw);

        assertThat(json).isEqualTo(
                "[{\"raw\":\"00000009\",\"len\":4},"
                + "{\"distinguisher\":3,\"color\":5,\"endpoint\":\"10.11.12.13\",\"endpoint_afi\":1}]");
    }

    private static String assertThatNoThrow(byte[] raw) {
        String[] holder = new String[1];
        assertThatCode(() -> holder[0] = SrPolicyJson.toJson(raw)).doesNotThrowAnyException();
        return holder[0];
    }
}
