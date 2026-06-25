package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.authlete.cbor.CBORItemList;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.util.JWKSUtils;

class OID4VPSessionTranscriptTest {

    @Test
    void shouldComputeValidSessionTranscript_OID4VPSpec() {
        // The test vector is the example in the OpenID4VP spec.
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-handover-and-sessiontranscr

        String respEncJwk = """
               {
                 "kty": "EC",
                 "crv": "P-256",
                 "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                 "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
                 "use": "enc",
                 "alg": "ECDH-ES",
                 "kid": "1"
               }
            """;

        CBORItemList sessionTranscript = OID4VPSessionTranscript.computeSessionTranscript_OID4VPSpec(
                "x509_san_dns:example.com",
                "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
                computeJwkThumbprint(respEncJwk),
                "https://example.com/response");

        assertEquals(str("""
            83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e
            ed494cefdd9d95240d254b046b11b68013722aad38ac
            """), Hex.toHexString(sessionTranscript.encode()));
    }

    @Test
    void shouldComputeValidSessionTranscript_ISOSpec() {
        // The test vector is the example in the ISO spec.
        // ISO/IEC TS 18013-7:2025 - § B.6

        String apu = "MTIzNDU2Nzg5MGFiY2RlZmdo";
        String mdocGeneratedNonce = new String(Base64Url.decode(apu), StandardCharsets.UTF_8);

        CBORItemList sessionTranscript = OID4VPSessionTranscript.computeSessionTranscript_ISOSpec(
                mdocGeneratedNonce, "example.com", "https://example.com/12345/response", "abcdefgh1234567890");

        assertEquals(str("""
            83f6f6835820da25c527e5fb75bc2dd31267c02237c4462ba0c1bf37071f692e7dd93b10ad0b5820f6ed8
            e3220d3c59a5f17eb45f48ab70aeecf9ee21744b1014982350bd96ac0c572616263646566676831323334
            353637383930
            """), Hex.toHexString(sessionTranscript.encode()));
    }

    private static byte[] computeJwkThumbprint(String jwkStr) {
        JWK jwk = JWKParser.create().parse(jwkStr).getJwk();
        String thumbprint = JWKSUtils.computeThumbprint(jwk);
        return Base64Url.decode(thumbprint);
    }

    private static String str(String input) {
        return input.replaceAll("\\s+", "");
    }
}
