package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants;
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
                "Unsupported dcql_query credential format for presentation validation: dc+sd-jwt", error.getMessage());
    }

    @Test
    void rejectsMismatchedDocType() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), "com.example.other");
        Credential credential = credentialWithClaims(claim("given-name", NAMESPACE, "given_name"));

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertEquals(
                "Presented mDoc docType does not match meta.doctype_value: expected 'com.example.doctype' but got 'com.example.other'",
                error.getMessage());
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
    void rejectsValidCborButMissingDocType() throws Exception {
        CBORPairList issuerSigned =
                new CBORPairList(new CBORPair(new CBORString(MdocConstants.L_NAME_SPACES), new CBORPairList()));

        CBORPairList document =
                new CBORPairList(new CBORPair(new CBORString(MdocConstants.L_ISSUER_SIGNED), issuerSigned));

        CBORItemList documents = new CBORItemList(List.of(document));
        CBORPairList deviceResponse =
                new CBORPairList(new CBORPair(new CBORString(MdocConstants.L_DOCUMENTS), documents));

        String validCborButInvalidMdoc =
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.encode());

        Credential credential = credentialWithClaims(claim("given-name", NAMESPACE, "given_name"));

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> capability.validatePresentation(credential, validCborButInvalidMdoc));
        assertTrue(error.getMessage().contains("Failed to parse"));
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

    @Test
    void rejectsPresentationWithMissingDocumentsField() throws Exception {
        Credential credential = credentialWithClaims();
        String invalidToken = "omdvY3VtZW50c4A";
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> capability.validatePresentation(credential, invalidToken));
        assertTrue(error.getMessage().contains("Failed to parse"));
    }

    @Test
    void rejectsPresentationWithZeroDocuments() throws Exception {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> capability.validatePresentation(credentialWithClaims(), buildDeviceResponseWithDocumentCount(0)));
        assertTrue(error.getMessage().contains("Failed to parse"));
    }

    @Test
    void rejectsPresentationWithMultipleDocuments() throws Exception {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> capability.validatePresentation(credentialWithClaims(), buildDeviceResponseWithDocumentCount(2)));
        assertTrue(error.getMessage().contains("Failed to parse"));
    }

    @Test
    void handlesPresentationWithMissingNamespaces() throws Exception {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> capability.validatePresentation(credentialWithClaims(), buildDeviceResponseWithoutNamespaces()));
        assertTrue(error.getMessage().contains("Failed to parse"));
    }

    @Test
    void rejectsClaimPathWithNullPath() throws Exception {
        Claim claimWithNullPath = new Claim();
        claimWithNullPath.setId("test-claim");
        claimWithNullPath.setPath(null);
        Credential credential = credentialWithClaims(claimWithNullPath);
        String token = mdocToken(Map.of(), DOC_TYPE);

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertTrue(error.getMessage().contains("Invalid mDoc claim path"));
        assertTrue(error.getMessage().contains("null"));
    }

    @Test
    void rejectsClaimPathWithSingleElement() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Claim claimWithSingleElement = new Claim();
        claimWithSingleElement.setId("test-claim");
        claimWithSingleElement.setPath(List.of("only-one-element"));
        Credential credential = credentialWithClaims(claimWithSingleElement);

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertTrue(error.getMessage().contains("Invalid mDoc claim path"));
        assertTrue(error.getMessage().contains("[only-one-element]"));
    }

    @Test
    void rejectsClaimPathWithThreeElements() throws Exception {
        String token = mdocToken(Map.of(NAMESPACE, Map.of("given_name", "Alice")), DOC_TYPE);
        Claim claimWithThreeElements = new Claim();
        claimWithThreeElements.setId("test-claim");
        claimWithThreeElements.setPath(List.of("one", "two", "three"));
        Credential credential = credentialWithClaims(claimWithThreeElements);

        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertTrue(error.getMessage().contains("Invalid mDoc claim path"));
        assertTrue(error.getMessage().contains("[one, two, three]"));
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

    private static String buildDeviceResponseWithDocumentCount(int documentCount) throws Exception {
        List<CBORPairList> documentList = new java.util.ArrayList<>();

        for (int i = 0; i < documentCount; i++) {
            CBORPairList issuerSigned =
                    new CBORPairList(new CBORPair(new CBORString(MdocConstants.L_NAME_SPACES), new CBORPairList()));

            CBORPairList document = new CBORPairList(
                    new CBORPair(new CBORString(MdocConstants.L_DOC_TYPE), new CBORString(DOC_TYPE)),
                    new CBORPair(new CBORString(MdocConstants.L_ISSUER_SIGNED), issuerSigned));

            documentList.add(document);
        }

        CBORItemList documents = new CBORItemList(documentList);
        CBORPairList deviceResponse =
                new CBORPairList(new CBORPair(new CBORString(MdocConstants.L_DOCUMENTS), documents));

        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.encode());
    }

    private static String buildDeviceResponseWithoutNamespaces() throws Exception {
        CBORPairList issuerSigned = new CBORPairList();

        CBORPairList document = new CBORPairList(
                new CBORPair(new CBORString(MdocConstants.L_DOC_TYPE), new CBORString(DOC_TYPE)),
                new CBORPair(new CBORString(MdocConstants.L_ISSUER_SIGNED), issuerSigned));

        CBORItemList documents = new CBORItemList(List.of(document));

        CBORPairList deviceResponse =
                new CBORPairList(new CBORPair(new CBORString(MdocConstants.L_DOCUMENTS), documents));

        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.encode());
    }
}
