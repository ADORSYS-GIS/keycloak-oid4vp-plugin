package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;

class MdocDcqlCredentialCapabilityTest extends MdocBaseTest {

    private final MdocDcqlCredentialCapability capability = new MdocDcqlCredentialCapability();

    @Test
    void formatReturnsMsoMdoc() {
        assertEquals("mso_mdoc", capability.format());
    }

    @Test
    void reportsPresentationPreValidationSupport() {
        assertTrue(capability.supportsPresentationPreValidation());
    }

    @Test
    void validatesMatchingDocTypeAndRequestedClaims() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice", "family_name", "Smith")), DOC_TYPE);
        Credential credential = credentialWithClaims(
                claim("given-name", NAMESPACE, "given_name"), claim("family-name", NAMESPACE, "family_name"));

        assertDoesNotThrow(() -> capability.validatePresentation(credential, token));
    }

    @Test
    void validatesIsoSpecSample() {
        String token = readResource("/mdoc/spec-sample.txt");
        Credential credential = credentialWithDocTypeAndClaims(
                "org.iso.18013.5.1.mDL", claim("given-name", "org.iso.18013.5.1", "given_name"));

        assertDoesNotThrow(() -> capability.validatePresentation(credential, token));
    }

    @Test
    void validatesPresentationWithNoRequestedClaims() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Credential credential = credentialWithClaims();

        assertDoesNotThrow(() -> capability.validatePresentation(credential, token));
    }

    @Test
    void rejectsUnsupportedCredentialFormat() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Credential credential = credentialWithClaims(claim("given-name", NAMESPACE, "given_name"));
        credential.setFormat(VCFormat.SD_JWT_VC);

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertEquals(
                "Unsupported dcql_query credential format for presentation validation: " + VCFormat.SD_JWT_VC,
                error.getMessage());
    }

    @Test
    void rejectsMismatchedDocType() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), "com.example.other");
        Credential credential = credentialWithClaims(claim("given-name", NAMESPACE, "given_name"));

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertEquals("Presented mDoc docType does not match meta.doctype_value: com.example.other", error.getMessage());
    }

    @Test
    void rejectsMissingRequestedClaim() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Credential credential = credentialWithClaims(claim("family-name", NAMESPACE, "family_name"));

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertEquals(
                "Presented mDoc does not satisfy DCQL claim path: [com.example.namespace1, family_name]",
                error.getMessage());
    }

    @Test
    void rejectsRequestedClaimFromDifferentNamespace() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Credential credential = credentialWithClaims(claim("given-name", "com.example.other-namespace", "given_name"));

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertEquals(
                "Presented mDoc does not satisfy DCQL claim path: [com.example.other-namespace, given_name]",
                error.getMessage());
    }

    @Test
    void validatesClaimSetsWhenOneOptionIsSatisfied() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Claim givenName = claim("given-name", NAMESPACE, "given_name");
        Claim familyName = claim("family-name", NAMESPACE, "family_name");
        Credential credential = credentialWithClaims(givenName, familyName);
        credential.setClaimSets(List.of(List.of("given-name", "family-name"), List.of("given-name")));

        assertDoesNotThrow(() -> capability.validatePresentation(credential, token));
    }

    @Test
    void rejectsClaimSetsWhenNoOptionIsSatisfied() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Claim givenName = claim("given-name", NAMESPACE, "given_name");
        Claim familyName = claim("family-name", NAMESPACE, "family_name");
        Credential credential = credentialWithClaims(givenName, familyName);
        credential.setClaimSets(List.of(List.of("given-name", "family-name")));

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertEquals("Presented mDoc does not satisfy any DCQL claim_sets option", error.getMessage());
    }

    @Test
    void doesNotTreatClaimValuesAsSecurityConstraint() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Claim givenName = claim("given-name", NAMESPACE, "given_name");
        givenName.setValues(List.of("Bob"));
        Credential credential = credentialWithClaims(givenName);

        assertDoesNotThrow(() -> capability.validatePresentation(credential, token));
    }

    @Test
    void rejectsMalformedPresentation() {
        Credential credential = credentialWithClaims(claim("given-name", NAMESPACE, "given_name"));

        assertThrows(IllegalArgumentException.class, () -> capability.validatePresentation(credential, "not-cbor"));
    }

    @Test
    void contributeVpFormatsSupportedConvertsJoseToCoseAlgorithms() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        capability.contributeVpFormatsSupported(vpFormat, List.of("ES256", "ES384"));

        assertNotNull(vpFormat.getMsoMdoc());
        assertEquals(List.of(-7, -35), vpFormat.getMsoMdoc().getIssuerAuthAlgValues());
        assertEquals(List.of(-7, -35), vpFormat.getMsoMdoc().getDeviceAuthAlgValues());
    }

    @Test
    void contributeVpFormatsSupportedDropsUnknownAlgorithms() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        capability.contributeVpFormatsSupported(vpFormat, List.of("UNKNOWN_ALG"));

        assertNotNull(vpFormat.getMsoMdoc());
        assertEquals(List.of(), vpFormat.getMsoMdoc().getIssuerAuthAlgValues());
        assertEquals(List.of(), vpFormat.getMsoMdoc().getDeviceAuthAlgValues());
    }

    @Test
    void contributeVpFormatsSupportedKeepsKnownAndDropsUnknown() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        capability.contributeVpFormatsSupported(vpFormat, List.of("ES256", "UNKNOWN_ALG", "EdDSA"));

        assertNotNull(vpFormat.getMsoMdoc());
        assertEquals(List.of(-7, -8), vpFormat.getMsoMdoc().getIssuerAuthAlgValues());
        assertEquals(List.of(-7, -8), vpFormat.getMsoMdoc().getDeviceAuthAlgValues());
    }

    @Test
    void contributeVpFormatsSupportedHandlesEdDSA() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        capability.contributeVpFormatsSupported(vpFormat, List.of("EdDSA"));

        assertNotNull(vpFormat.getMsoMdoc());
        assertEquals(List.of(-8), vpFormat.getMsoMdoc().getIssuerAuthAlgValues());
        assertEquals(List.of(-8), vpFormat.getMsoMdoc().getDeviceAuthAlgValues());
    }

    private static String mdocToken(Map<String, Object> claims, String docType) throws Exception {
        return buildDeviceResponse(getDefaultMdocVerificationOpts().build(), claims, docType)
                .encodeToBase64Url();
    }

    private static Credential credentialWithClaims(Claim... claims) {
        return credentialWithDocTypeAndClaims(DOC_TYPE, claims);
    }

    private static Credential credentialWithDocTypeAndClaims(String docType, Claim... claims) {
        Meta meta = new Meta();
        meta.setDoctypeValue(docType);

        Credential credential = new Credential();
        credential.setId("mdoc-credential");
        credential.setFormat("mso_mdoc");
        credential.setMeta(meta);
        credential.setClaims(List.of(claims));
        return credential;
    }

    private static Claim claim(String id, String namespace, String elementIdentifier) {
        Claim claim = new Claim();
        claim.setId(id);
        claim.setPath(List.of(namespace, elementIdentifier));
        return claim;
    }
}
