package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_FIELD;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_LIST_FIELD;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cose.COSEEC2Key;
import com.authlete.cose.COSESign1;
import com.authlete.mdoc.DeviceResponse;
import com.authlete.mdoc.DeviceSigned;
import com.authlete.mdoc.Document;
import com.authlete.mdoc.IssuerNameSpaces;
import com.authlete.mdoc.IssuerSigned;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.CborUtil;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationOpts;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.TestTruststoreProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.models.AuthenticatorConfigModel;

public class MdocRevocationStatusTest extends MdocBaseTest {

    private static final String STATUS_LIST_URI = "https://status.example.com/list";

    // IETF 1-bit small test vector: 16 entries, idx 0 = INVALID (1), idx 1 = VALID (0)
    private static final String IETF_1BIT_SMALL_TEST_VECTOR = "eNrbuRgAAhcBXQ";

    private MdocVerificationOpts opts;
    private TrustAnchorProvider trust;
    private StatusListJwtFetcher mockFetcher;

    @BeforeEach
    void setUp() throws Exception {
        opts = getDefaultMdocVerificationOpts().build();
        trust = new TestTruststoreProvider(getIssuerCertRef1());

        mockFetcher = uri -> {
            String mockJwtPayload = """
                    {
                        "status_list": {
                            "bits": 1,
                            "lst": "%s"
                        }
                    }
                    """.formatted(IETF_1BIT_SMALL_TEST_VECTOR);
            String header = "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCJ9"; // {"typ":"statuslist+jwt"}
            String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(mockJwtPayload.getBytes());
            return header + "." + payload + ".mock_signature";
        };
    }

    @Test
    public void shouldExtractMsoAsJson() throws Exception {
        String mdoc = buildDeviceResponse(opts).encodeToBase64Url();
        JsonNode mso = MdocCredentialVerifier.extractMsoPayload(mdoc);

        assertNotNull(mso);
        assertEquals("1.0", mso.get("version").asText());
        assertEquals("SHA-256", mso.get("digestAlgorithm").asText());
        assertNotNull(mso.get("valueDigests"));
        assertNotNull(mso.get("deviceKeyInfo"));
        assertNotNull(mso.get("validityInfo"));
    }

    @Test
    public void shouldVerifyMdoc_WhenRevocationEnforcementDisabled() throws Exception {
        String mdoc = buildDeviceResponse(opts).encodeToBase64Url();
        assertDoesNotThrow(() -> new MdocVerificationContext(mdoc).verifyPresentation(opts, null, trust));
    }

    @Test
    public void shouldFail_WhenRevocationEnforcedAndStatusMissing() throws Exception {
        String mdoc = buildDeviceResponse(opts).encodeToBase64Url();
        var mso = MdocCredentialVerifier.extractMsoPayload(mdoc);

        assertNull(mso.get(STATUS_FIELD));
        ReferencedTokenValidationException exception =
                assertThrows(ReferencedTokenValidationException.class, () -> new ReferencedTokenValidator(mockFetcher)
                        .validate(mso));
        assertTrue(exception.getMessage().contains("Missing required '" + STATUS_FIELD + "'"));
    }

    @Test
    public void shouldPass_WhenRevocationEnforcedAndStatusValid() throws Exception {
        String mdoc = buildMdocWithStatus(1);
        assertDoesNotThrow(() ->
                new ReferencedTokenValidator(mockFetcher).validate(MdocCredentialVerifier.extractMsoPayload(mdoc)));
    }

    @Test
    public void shouldConstructVerifier_WithFetcher() throws Exception {
        var verifier = new MdocCredentialVerifier(mockFetcher);
        assertEquals(CredentialFormat.MSO_MDOC, verifier.format());
    }

    @Test
    public void shouldFailVerification_WhenCredentialRevoked() throws Exception {
        var authConfig = new AuthenticatorConfigModel();
        authConfig.getConfig().put(ENFORCE_REVOCATION_STATUS_CONFIG, "true");

        var requestObject = new RequestObject()
                .setClientId("x509_san_dns:example.com")
                .setNonce("exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA")
                .setResponseUri("https://example.com/response");

        var authCtx = new AuthorizationContext().setRequestObject(requestObject);

        var context = mock(AuthenticationFlowContext.class);
        when(context.getAuthenticatorConfig()).thenReturn(authConfig);

        var credential = new CredentialRequirement()
                .setId("test")
                .setCredentialTypes(List.of(DOC_TYPE))
                .setTrust(List.of(new TrustPolicy().setType(TrustPolicy.X5C).setAnchors(List.of(getIssuerCertRef1()))));

        var verifier = new MdocCredentialVerifier(mockFetcher);

        // Build mDoc with opts matching what verifyCredential will derive from the requestObject
        byte[] thumbprint = MdocCredentialVerifier.computeJwkThumbprint(requestObject);
        var optsFromRequest = MdocVerificationOpts.builder()
                .withClientId(requestObject.getClientId())
                .withOid4vpNonce(requestObject.getNonce())
                .withResponseUri(requestObject.getResponseUri())
                .withJwkThumbprint(thumbprint)
                .build();

        String validMdoc = buildMdocWithStatus(1, optsFromRequest);
        assertDoesNotThrow(() -> verifier.verifyCredential(context, authCtx, credential, validMdoc, false));

        String revokedMdoc = buildMdocWithStatus(0, optsFromRequest);
        VerificationException exception = assertThrows(
                VerificationException.class,
                () -> verifier.verifyCredential(context, authCtx, credential, revokedMdoc, false));
        assertTrue(exception.getMessage().contains("Token status verification failed"));
    }

    @Test
    public void shouldFail_WhenRevocationEnforcedAndStatusInvalid() throws Exception {
        String mdoc = buildMdocWithStatus(0);
        ReferencedTokenValidationException exception =
                assertThrows(ReferencedTokenValidationException.class, () -> new ReferencedTokenValidator(mockFetcher)
                        .validate(MdocCredentialVerifier.extractMsoPayload(mdoc)));
        assertTrue(exception.getMessage().contains("Token status is not valid"));
    }

    private String buildMdocWithStatus(int idx) throws Exception {
        return buildMdocWithStatus(idx, opts);
    }

    private String buildMdocWithStatus(int idx, MdocVerificationOpts mdocOpts) throws Exception {
        DeviceResponse dr = buildDeviceResponse(mdocOpts);
        Document doc = extractDocument(dr);
        IssuerSigned issuerSigned =
                (IssuerSigned) doc.findByKey(MdocConstants.L_ISSUER_SIGNED).getValue();

        CBORItemList issuerAuthList = (CBORItemList)
                issuerSigned.findByKey(MdocConstants.L_ISSUER_AUTH).getValue();
        CBORPairList originalMso =
                (CBORPairList) CborUtil.unwrap(COSESign1.build(issuerAuthList).getPayload());

        CBORPairList msoWithStatus = getCborPairList(idx, originalMso);

        COSESign1 newIssuerAuth = signRawMso(msoWithStatus, getIssuerKeyRef1(), List.of(getIssuerCertRef1()));
        IssuerSigned newIssuerSigned = new IssuerSigned(
                (IssuerNameSpaces)
                        issuerSigned.findByKey(MdocConstants.L_NAME_SPACES).getValue(),
                newIssuerAuth);

        DeviceResponse newDr = new DeviceResponse(List.of(new Document(
                DOC_TYPE,
                newIssuerSigned,
                (DeviceSigned) doc.findByKey(MdocConstants.L_DEVICE_SIGNED).getValue(),
                null)));
        return newDr.encodeToBase64Url();
    }

    private static @NotNull CBORPairList getCborPairList(int idx, CBORPairList originalMso) {
        CBORPairList statusList = new CBORPairList(
                new CBORPair(new CBORString("idx"), new CBORInteger(idx)),
                new CBORPair(new CBORString("uri"), new CBORString(MdocRevocationStatusTest.STATUS_LIST_URI)));
        CBORPairList statusWrapper = new CBORPairList(new CBORPair(new CBORString(STATUS_LIST_FIELD), statusList));
        CBORPair statusPair = new CBORPair(new CBORString(STATUS_FIELD), statusWrapper);

        List<CBORPair> newPairs = new ArrayList<>(originalMso.getPairs());
        newPairs.add(statusPair);
        CBORPairList msoWithStatus = new CBORPairList(newPairs);
        return msoWithStatus;
    }

    private static COSESign1 signRawMso(CBORPairList mso, COSEEC2Key issuerKey, List<X509Certificate> x5chain)
            throws Exception {
        return MdocBaseTest.signRawCbor(mso, issuerKey, x5chain);
    }
}
