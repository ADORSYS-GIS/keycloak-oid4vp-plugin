package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;

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

        new MdocVerificationContext(mdoc).verifyPresentation(null, opts, null);
    }
}
