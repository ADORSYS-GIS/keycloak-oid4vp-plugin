package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.mdoc.DeviceResponse;
import com.authlete.mdoc.Document;
import com.authlete.mdoc.IssuerSigned;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.ArrayList;
import java.util.Base64;
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
        Document validDocument = extractDocument(buildDeviceResponse());
        CBORPairList document = new CBORPairList(
                new CBORPair(
                        new CBORString(MdocConstants.L_ISSUER_SIGNED),
                        validDocument.findByKey(MdocConstants.L_ISSUER_SIGNED).getValue()),
                new CBORPair(
                        new CBORString(MdocConstants.L_DEVICE_SIGNED),
                        validDocument.findByKey(MdocConstants.L_DEVICE_SIGNED).getValue()));

        CBORItemList documents = new CBORItemList(List.of(document));
        CBORPairList deviceResponse = new CBORPairList(
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString(MdocConstants.L_STATUS), new CBORInteger(MdocConstants.V_STATUS_OK)),
                new CBORPair(new CBORString(MdocConstants.L_DOCUMENTS), documents));

        String validCborButInvalidMdoc =
                Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.encode());

        Credential credential = credentialWithClaims(claim("given-name", NAMESPACE, "given_name"));

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> capability.validatePresentation(credential, validCborButInvalidMdoc));
        assertTrue(error.getMessage().contains("Failed to parse"));
        assertTrue(error.getCause().getMessage().contains("docType"));
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
        CBORPairList deviceResponse = new CBORPairList(
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString(MdocConstants.L_STATUS), new CBORInteger(MdocConstants.V_STATUS_OK)));
        String invalidToken = Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.encode());

        VerificationException error = assertThrows(
                VerificationException.class, () -> capability.validatePresentation(credential, invalidToken));
        assertTrue(error.getMessage().contains("missing the documents field"));
    }

    @Test
    void rejectsPresentationWithZeroDocuments() throws Exception {
        VerificationException error = assertThrows(
                VerificationException.class,
                () -> capability.validatePresentation(credentialWithClaims(), buildDeviceResponseWithDocumentCount(0)));
        assertTrue(error.getMessage().contains("exactly one document"));
    }

    @Test
    void rejectsPresentationWithMultipleDocuments() throws Exception {
        VerificationException error = assertThrows(
                VerificationException.class,
                () -> capability.validatePresentation(credentialWithClaims(), buildDeviceResponseWithDocumentCount(2)));
        assertTrue(error.getMessage().contains("exactly one document"));
    }

    @Test
    void handlesPresentationWithMissingNamespaces() throws Exception {
        String token = buildDeviceResponseWithoutNamespaces();
        assertDoesNotThrow(() -> capability.validatePresentation(credentialWithClaims(), token));

        Credential credential = credentialWithClaims(claim("given-name", NAMESPACE, "given_name"));
        VerificationException error =
                assertThrows(VerificationException.class, () -> capability.validatePresentation(credential, token));
        assertEquals(
                "Presented mDoc does not satisfy DCQL claim path: [com.example.namespace1, given_name]",
                error.getMessage());
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

    private String buildDeviceResponseWithDocumentCount(int documentCount) throws Exception {
        DeviceResponse validDr = buildDeviceResponse();
        Document validDoc = extractDocument(validDr);

        List<CBORItem> documentList = new ArrayList<>();
        for (int i = 0; i < documentCount; i++) {
            documentList.add(validDoc);
        }

        CBORItemList documents = new CBORItemList(documentList);
        CBORPairList deviceResponse = new CBORPairList(
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString(MdocConstants.L_STATUS), new CBORInteger(MdocConstants.V_STATUS_OK)),
                new CBORPair(new CBORString(MdocConstants.L_DOCUMENTS), documents));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.encode());
    }

    private String buildDeviceResponseWithoutNamespaces() throws Exception {
        DeviceResponse validDr = buildDeviceResponse();
        Document validDoc = extractDocument(validDr);

        IssuerSigned issuerSigned =
                (IssuerSigned) validDoc.findByKey(MdocConstants.L_ISSUER_SIGNED).getValue();

        CBORPairList newIssuerSigned = new CBORPairList(new CBORPair(
                new CBORString(MdocConstants.L_ISSUER_AUTH),
                issuerSigned.findByKey(MdocConstants.L_ISSUER_AUTH).getValue()));

        CBORPairList newDocument = new CBORPairList(
                new CBORPair(
                        new CBORString(MdocConstants.L_DOC_TYPE),
                        validDoc.findByKey(MdocConstants.L_DOC_TYPE).getValue()),
                new CBORPair(new CBORString(MdocConstants.L_ISSUER_SIGNED), newIssuerSigned),
                new CBORPair(
                        new CBORString(MdocConstants.L_DEVICE_SIGNED),
                        validDoc.findByKey(MdocConstants.L_DEVICE_SIGNED).getValue()));

        CBORItemList documents = new CBORItemList(List.of(newDocument));

        CBORPairList deviceResponse = new CBORPairList(
                new CBORPair(new CBORString("version"), new CBORString("1.0")),
                new CBORPair(new CBORString(MdocConstants.L_STATUS), new CBORInteger(MdocConstants.V_STATUS_OK)),
                new CBORPair(new CBORString(MdocConstants.L_DOCUMENTS), documents));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(deviceResponse.encode());
    }
}
