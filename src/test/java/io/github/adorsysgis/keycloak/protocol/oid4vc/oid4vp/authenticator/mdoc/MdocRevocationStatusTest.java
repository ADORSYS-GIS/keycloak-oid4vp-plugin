package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_FIELD;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_LIST_FIELD;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.mdoc.DeviceResponse;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationOpts;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.TestTruststoreProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
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
    public void shouldFail_WhenRevocationEnforcedAndStatusMissing() throws Exception {
        String mdoc = buildDeviceResponse(opts).encodeToBase64Url();
        var ctx = new MdocVerificationContext(mdoc);
        ctx.verifyPresentation(opts, null, trust);
        var mso = ctx.getVerifiedMsoPayload();

        assertNull(mso.get(STATUS_FIELD));
        ReferencedTokenValidationException exception =
                assertThrows(ReferencedTokenValidationException.class, () -> new ReferencedTokenValidator(mockFetcher)
                        .validate(mso));
        assertTrue(exception.getMessage().contains("Missing required '" + STATUS_FIELD + "'"));
    }

    @Test
    public void shouldPass_WhenRevocationEnforcedAndStatusValid() throws Exception {
        String mdoc = buildMdocWithStatus(1);
        var ctx = new MdocVerificationContext(mdoc);
        ctx.verifyPresentation(opts, null, trust);
        assertDoesNotThrow(() -> new ReferencedTokenValidator(mockFetcher).validate(ctx.getVerifiedMsoPayload()));
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
        var ctx = new MdocVerificationContext(mdoc);
        ctx.verifyPresentation(opts, null, trust);
        ReferencedTokenValidationException exception =
                assertThrows(ReferencedTokenValidationException.class, () -> new ReferencedTokenValidator(mockFetcher)
                        .validate(ctx.getVerifiedMsoPayload()));
        assertTrue(exception.getMessage().contains("Token status is not valid"));
    }

    private String buildMdocWithStatus(int idx) throws Exception {
        return buildMdocWithStatus(idx, opts);
    }

    private String buildMdocWithStatus(int idx, MdocVerificationOpts mdocOpts) throws Exception {
        DeviceResponse dr = buildDeviceResponse(mdocOpts);
        DeviceResponse modified = withModifiedMso(dr, mso -> getCborPairList(idx, mso));
        return modified.encodeToBase64Url();
    }

    private static CBORPairList getCborPairList(int idx, CBORPairList originalMso) {
        CBORPairList statusList = new CBORPairList(
                new CBORPair(new CBORString("idx"), new CBORInteger(idx)),
                new CBORPair(new CBORString("uri"), new CBORString(MdocRevocationStatusTest.STATUS_LIST_URI)));
        CBORPairList statusWrapper = new CBORPairList(new CBORPair(new CBORString(STATUS_LIST_FIELD), statusList));
        CBORPair statusPair = new CBORPair(new CBORString(STATUS_FIELD), statusWrapper);

        List<CBORPair> newPairs = new ArrayList<>(originalMso.getPairs());
        newPairs.add(statusPair);
        return new CBORPairList(newPairs);
    }
}
