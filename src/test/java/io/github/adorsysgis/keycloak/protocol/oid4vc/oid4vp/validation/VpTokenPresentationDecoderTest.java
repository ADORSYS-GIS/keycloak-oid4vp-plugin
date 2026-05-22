package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class VpTokenPresentationDecoderTest {

    private static final String RAW_SD_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature~disclosure";

    @Test
    void returnsRawSdJwtWithoutDecoding() {
        assertEquals(RAW_SD_JWT, VpTokenPresentationDecoder.decodeIfBase64Url(RAW_SD_JWT));
    }

    @Test
    void decodesBase64UrlWrappedPresentation() {
        String wrapped = Base64.getUrlEncoder().encodeToString(RAW_SD_JWT.getBytes(StandardCharsets.UTF_8));
        assertEquals(RAW_SD_JWT, VpTokenPresentationDecoder.decodeIfBase64Url(wrapped));
    }

    @Test
    void detectsCompactJwtShape() {
        assertTrue(VpTokenPresentationDecoder.looksLikeSdJwtPresentation(RAW_SD_JWT));
        assertFalse(VpTokenPresentationDecoder.looksLikeSdJwtPresentation("not-a-jwt"));
    }

    @Test
    void leavesNonJwtInputUntouchedWhenNotWrapped() {
        String invalid = "not-a-jwt-or-wrapper";
        assertEquals(invalid, VpTokenPresentationDecoder.decodeIfBase64Url(invalid));
    }
}
