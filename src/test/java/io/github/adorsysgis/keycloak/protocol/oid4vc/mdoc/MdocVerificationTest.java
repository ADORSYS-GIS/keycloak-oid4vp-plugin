package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.truststore.TruststoreProvider;

public class MdocVerificationTest extends MdocBaseTest {

    @Test
    public void shouldVerifyValidMdocSuccessfully_SpecSample() throws VerificationException {
        String mdoc = readResource("/mdoc/spec-sample.txt");

        TruststoreProvider trust = new StaticTruststoreProvider(getSpecSampleCert());

        MdocVerificationOpts opts = MdocVerificationOpts.builder()
                .withClientId("example.com")
                .withOid4vpNonce("abcdefgh1234567890")
                .withMdocGeneratedNonce("1234567890abcdefgh")
                .withResponseUri("https://example.com/12345/response")
                .build();

        PresentationRequirements reqs = (JsonNode nsClaims) -> {
            assertEquals(1, nsClaims.size(), "There should be exactly one namespace");
            JsonNode claims = nsClaims.get("org.iso.18013.5.1");
            assertNotNull(claims, "The ISO node should exist");

            assertEquals("USA", claims.get("un_distinguishing_sign").asText());
            assertEquals("ABCD1234", claims.get("document_number").asText());
            assertEquals("Alice", claims.get("given_name").asText());
            assertEquals("Smith", claims.get("family_name").asText());

            JsonNode privileges = claims.get("driving_privileges");
            assertEquals(2, privileges.size(), "Should have exactly 2 driving privilege categories");
            assertEquals("B", privileges.get(0).get("vehicle_category_code").asText());
            assertEquals("BE", privileges.get(1).get("vehicle_category_code").asText());
        };

        try {
            // The test vector dates back to 2024, so we move back in time to bypass expiration checks.
            Time.setOffset(1714338150 - Time.currentTime());
            // Act: Verify the presentation using the provided options and requirements.
            new MdocVerificationContext(mdoc).verifyPresentation(opts, reqs, trust);
        } finally {
            Time.setOffset(0); // Reset time offset after test
        }
    }

    @Test
    public void shouldVerifyValidMdocSuccessfully_OpenID4VPSpecTranscript() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts).encodeToBase64Url();
        TruststoreProvider trust = new StaticTruststoreProvider(getIssuerCertRef1());
        new MdocVerificationContext(mdoc).verifyPresentation(opts, null, trust);
    }

    private static String getSpecSampleCert() {
        return """
            MIICXDCCAgGgAwIBAgIKR1IJyTwoAKFf/zAKBggqhkjOPQQDAjBFMQswCQYDVQQG
            EwJVUzEpMCcGA1UEAwwgSVNPMTgwMTMtNSBUZXN0IENlcnRpZmljYXRlIElBQ0Ex
            CzAJBgNVBAgMAk5ZMB4XDTI0MDQyODIxMDIyM1oXDTI1MDcyOTIxMDIyM1owRDEL
            MAkGA1UEBhMCVVMxKDAmBgNVBAMMH0lTTzE4MDEzLTUgVGVzdCBDZXJ0aWZpY2F0
            ZSBEU0MxCzAJBgNVBAgMAk5ZMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN04V
            oqv1bGCkVaXMXxWZ9yEG9PALWgfUxo/rzmwcoaat5A9WyptKUcAEZNY+tyduGU9t
            AusOxkfTeCCd1+PDvKOB2TCB1jAdBgNVHQ4EFgQUZSkNyyy+We9Wu99FbU/4pFp9
            7lowHwYDVR0jBBgwFoAUTP+VJeBlm1DsHEMKWnKNxBtNOs8wDgYDVR0PAQH/BAQD
            AgeAMB0GA1UdEQQWMBSBEmV4YW1wbGVAaXNvbWRsLmNvbTAdBgNVHRIEFjAUgRJl
            eGFtcGxlQGlzb21kbC5jb20wLwYDVR0fBCgwJjAkoCKgIIYeaHR0cHM6Ly9leGFt
            cGxlLmNvbS9JU09tREwuY3JsMBUGA1UdJQEB/wQLMAkGByiBjF0FAQIwCgYIKoZI
            zj0EAwIDSQAwRgIhAK/DzBi2gOVCUHOoxgXpTQpcrV8ULl/Q0ROYqS3Gr6NZAiEA
            o4i3TOyNcI7ZMm+0JrzUdAM6gM4K9zhOnmPOnitbtUM=
        """;
    }
}
