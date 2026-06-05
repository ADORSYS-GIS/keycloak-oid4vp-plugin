package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class VpTokenPresentationDecoderTest {

    @Test
    void returnsPlainSdJwtUnchanged() {
        String sdJwt = "eyJhbGci.issuer~disclosure~kb-jwt";
        assertEquals(sdJwt, VpTokenPresentationDecoder.decodeIfBase64Url(sdJwt));
    }

    @Test
    void decodesBase64UrlEncodedPresentation() {
        String sdJwt = "eyJhbGci.issuer~disclosure~kb-jwt";
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(sdJwt.getBytes(StandardCharsets.UTF_8));
        assertEquals(sdJwt, VpTokenPresentationDecoder.decodeIfBase64Url(encoded));
    }
}
