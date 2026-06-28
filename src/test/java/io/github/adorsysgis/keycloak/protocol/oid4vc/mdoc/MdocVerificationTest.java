package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.consumer.PresentationRequirements;

public class MdocVerificationTest extends MdocBaseTest {

    @Test
    @Disabled
    public void shouldVerifyValidMdocSuccessfully() throws Exception {
        String mdoc = buildDeviceResponse().encodeToBase64Url();
        new MdocVerificationContext(mdoc).verifyPresentation(null, null, null);
    }

    @Test
    public void shouldVerifyValidMdocSuccessfully_SpecSample() throws VerificationException {
        String mdoc = readResource("/mdoc/spec-sample.txt");

        // The test vector dates back to 2024, so we use a 50-year clock skew to bypass expiration checks.
        int clockSkew = 50 * 365 * 24 * 60 * 60; // 50 years in seconds
        MdocVerificationOpts opts = MdocVerificationOpts.builder(clockSkew)
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

        // Act: Verify the presentation using the provided options and requirements.
        new MdocVerificationContext(mdoc).verifyPresentation(null, opts, reqs);
    }
}
