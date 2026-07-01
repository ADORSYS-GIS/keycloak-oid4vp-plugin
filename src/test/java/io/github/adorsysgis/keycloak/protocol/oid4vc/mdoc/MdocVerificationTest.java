package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authlete.mdoc.DeviceResponse;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.JavaAlgorithm;
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
                .withFallbackToIsoSpecSessionTranscript(true)
                .build();

        PresentationRequirements reqs = (JsonNode payload) -> {
            assertEquals(
                    "org.iso.18013.5.1.mDL",
                    payload.get(MdocConstants.L_DOC_TYPE).asText());

            JsonNode nsClaims = payload.get(MdocConstants.L_NAME_SPACES);
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
            new MdocVerificationContext(mdoc).verifyPresentation(opts, reqs, trust);
        } finally {
            Time.setOffset(0);
        }
    }

    @Test
    public void shouldVerifyValidMdocSuccessfully_OpenID4VPSpecTranscript() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts).encodeToBase64Url();
        TruststoreProvider trust = new StaticTruststoreProvider(getIssuerCertRef1());
        new MdocVerificationContext(mdoc).verifyPresentation(opts, null, trust);
    }

    @Test
    public void shouldFail_OnExpiredResponses() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts).encodeToBase64Url();
        TruststoreProvider trust = new StaticTruststoreProvider(getIssuerCertRef1());

        try {
            Time.setOffset(DEFAULT_RESPONSE_VALIDITY_MINS * 60 + 300);
            verifyFails(mdoc, opts, trust, "Validity information verification failed", "Token has expired");
        } finally {
            Time.setOffset(0);
        }
    }

    @Test
    public void shouldFail_OnNonZeroStatus() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        DeviceResponse dr = buildDeviceResponse(opts);
        String mdoc = new DeviceResponse("1.0", List.of(extractDocument(dr)), null, /*status*/ 10).encodeToBase64Url();
        verifyFails(mdoc, opts, null, "mDoc response status is not OK: status=10");
    }

    @Test
    public void shouldFail_OnMultipleDocuments() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        DeviceResponse dr = buildDeviceResponse(opts);
        String mdoc = new DeviceResponse(List.of(extractDocument(dr), extractDocument(dr))).encodeToBase64Url();
        verifyFails(mdoc, opts, null, "Expected 1 document but received 2");
    }

    @Test
    public void shouldFail_OnZeroDocuments() {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = new DeviceResponse("1.0", List.of(), null, 0).encodeToBase64Url();
        verifyFails(mdoc, opts, null, "Expected 1 document but received 0");
    }

    @Test
    public void shouldFail_OnMissingDocuments() {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = new DeviceResponse("1.0", null, null, 0).encodeToBase64Url();
        verifyFails(mdoc, opts, null, "mDoc response is missing the 'documents' field");
    }

    @Test
    public void shouldFail_OnIssuerKeyNotMatchingAttachedCert() throws Exception {
        // Sign with the device key (PKIX-acceptable against the ref1 cert), but attach the
        // ref1 issuer cert in x5chain: PKIX validates, then the COSE signature check fails
        // because the leaf's public key does not match the actual signer.
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts, ctx -> {
                    ctx.signingKey = getDeviceKeyRef1();
                    ctx.certChain = List.of(getIssuerCertRef1());
                    return ctx.signMsoAndWrap();
                })
                .encodeToBase64Url();
        verifyFails(
                mdoc,
                opts,
                new StaticTruststoreProvider(getIssuerCertRef1()),
                "Issuer signature could not be verified",
                "COSE signature verification failed");
    }

    @Test
    public void shouldFail_OnMissingIssuerCert() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts, ctx -> {
                    ctx.certChain = List.of();
                    return ctx.signMsoAndWrap();
                })
                .encodeToBase64Url();
        verifyFails(mdoc, opts, new StaticTruststoreProvider(getIssuerCertRef1()), "Certificate chain is empty");
    }

    @Test
    public void shouldFail_OnIssuerCertNotTrusted() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts).encodeToBase64Url();
        verifyFails(
                mdoc,
                opts,
                new StaticTruststoreProvider(toCert(getSpecSampleCert())),
                "Certificate chain validation failed",
                "Path does not chain with any of the trust anchors");
    }

    @Test
    public void shouldFail_OnDeviceSignatureWithWrongSessionTranscript() throws Exception {
        // Signed under optsA, verified under optsB - both session transcripts (OpenID4VP and
        // ISO) will mismatch so device key binding fails.
        MdocVerificationOpts signingOpts = getDefaultMdocVerificationOpts().build();
        MdocVerificationOpts verifyingOpts = getDefaultMdocVerificationOpts()
                .withClientId("x509_san_dns:other-relying-party.example.com")
                .build();
        String mdoc = buildDeviceResponse(signingOpts).encodeToBase64Url();
        verifyFails(
                mdoc,
                verifyingOpts,
                new StaticTruststoreProvider(getIssuerCertRef1()),
                "Device signature could not be verified",
                "COSE signature verification failed");
    }

    @Test
    public void shouldFail_OnMissingMdocGeneratedNonceWithIsoFallbackEnabled() throws Exception {
        MdocVerificationOpts signingOpts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(signingOpts).encodeToBase64Url();

        MdocVerificationOpts verifyingOpts = getDefaultMdocVerificationOpts()
                .withClientId(null) // so first attempt with OpenID4VP session transcript fail fast
                .withFallbackToIsoSpecSessionTranscript(true)
                .build();

        verifyFails(
                mdoc,
                verifyingOpts,
                new StaticTruststoreProvider(getIssuerCertRef1()),
                "Failed to compute session transcript for device binding verification",
                "Cannot compute handover: 'mdoc_generated_nonce' must not be null");
    }

    @Test
    public void shouldFail_OnClaimNotProtectedByMsoDigest() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts, ctx -> {
                    ctx.mso = rebuildMso(
                            ctx.mso,
                            withValueDigestsExcluding(extractValueDigests(ctx.mso), NAMESPACE),
                            JavaAlgorithm.SHA256);
                    return ctx.signMsoAndWrap();
                })
                .encodeToBase64Url();
        verifyFails(
                mdoc, opts, new StaticTruststoreProvider(getIssuerCertRef1()), "No value digests matching namespace");
    }

    @Test
    public void shouldFail_OnMismatchedMsoDigest() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts, ctx -> {
                    ctx.mso = rebuildMso(
                            ctx.mso, withTamperedDigest(extractValueDigests(ctx.mso), NAMESPACE), JavaAlgorithm.SHA256);
                    return ctx.signMsoAndWrap();
                })
                .encodeToBase64Url();
        verifyFails(mdoc, opts, new StaticTruststoreProvider(getIssuerCertRef1()), "Digest mismatch");
    }

    @Test
    public void shouldFail_OnUnsupportedDigestAlgorithm() throws Exception {
        // Re-build MSO with an algorithm not on the allow-list. The digests themselves are
        // byte-identical to the standard SHA-256 digests so verification fails on the
        // algorithm allow-list check, not on a digest mismatch.
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = buildDeviceResponse(opts, ctx -> {
                    ctx.mso = rebuildMso(ctx.mso, extractValueDigests(ctx.mso), "MD5");
                    return ctx.signMsoAndWrap();
                })
                .encodeToBase64Url();
        verifyFails(mdoc, opts, new StaticTruststoreProvider(getIssuerCertRef1()), "Invalid digest algorithm: MD5");
    }

    @Test
    public void shouldFail_OnDeviceMacInsteadOfDeviceSignature() throws Exception {
        MdocVerificationOpts opts = getDefaultMdocVerificationOpts().build();
        String mdoc = withDeviceMac(buildDeviceResponse(opts)).encodeToBase64Url();
        verifyFails(
                mdoc,
                opts,
                new StaticTruststoreProvider(getIssuerCertRef1()),
                "Device key binding verification failed: missing device signature");
    }

    /**
     * Asserts that verifying {@code mdoc} raises a {@link VerificationException} whose message
     * contains {@code expectedMessageFragment}. When {@code expectedCauseMessageFragment} is
     * non-null, also asserts that the cause's message contains it.
     */
    private static void verifyFails(
            String mdoc,
            MdocVerificationOpts opts,
            TruststoreProvider trust,
            String expectedMessageFragment,
            String expectedCauseMessageFragment) {
        var exception = assertThrows(VerificationException.class, () -> new MdocVerificationContext(mdoc)
                .verifyPresentation(opts, null, trust));
        assertErrorFragment(exception.getMessage(), expectedMessageFragment);
        if (expectedCauseMessageFragment != null) {
            assertNotNull(exception.getCause(), "Main exception should have linked a cause");
            assertErrorFragment(exception.getCause().getMessage(), expectedCauseMessageFragment);
        }
    }

    /** Convenience overload that only checks the top-level exception message. */
    private static void verifyFails(
            String mdoc, MdocVerificationOpts opts, TruststoreProvider trust, String expectedMessageFragment) {
        verifyFails(mdoc, opts, trust, expectedMessageFragment, null);
    }

    private static void assertErrorFragment(String actual, String expected) {
        assertTrue(actual.contains(expected), () -> "Expected error fragment '" + expected + "' but was: " + actual);
    }
}
