package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.sdjwt;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.ALLOW_MISSING_STATUS_CLAIM_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.VERIFY_ISSUER_CLAIM_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_FIELD;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_LIST_FIELD;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_CNF;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_EXP;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_JWK;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.ContextBuilder;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.util.JsonSerialization;

/**
 * Verifies the revocation status handling of {@link SdJwtCredentialVerifier}: the strict default,
 * the {@code allowMissingStatusClaim} tolerance, and the guarantee that present-but-revoked status
 * claims are still rejected when the tolerance is enabled.
 */
class SdJwtRevocationStatusTest {

    private static final String VCT = "https://credentials.example.com/identity_credential";
    private static final String NONCE = "nonce-value";
    private static final String AUD = "https://verifier.example";
    private static final String STATUS_LIST_URI = "https://status.example.com/list";

    // IETF 1-bit small test vector: 16 entries, idx 0 = INVALID (1), idx 1 = VALID (0)
    private static final String IETF_1BIT_SMALL_TEST_VECTOR = "eNrbuRgAAhcBXQ";

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(SdJwtRevocationStatusTest.class.getClassLoader());
    }

    private final StatusListJwtFetcher mockFetcher = uri -> {
        String mockJwtPayload = """
                {
                    "sub": "%s",
                    "iat": 1700000000,
                    "exp": 9999999999,
                    "status_list": {
                        "bits": 1,
                        "lst": "%s"
                    }
                }
                """.formatted(uri, IETF_1BIT_SMALL_TEST_VECTOR);
        String header = "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCJ9"; // {"typ":"statuslist+jwt"}
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(mockJwtPayload.getBytes());
        return header + "." + payload + ".mock_signature";
    };

    @Test
    void shouldFail_WhenRevocationEnforcedAndStatusMissing() throws Exception {
        var verifier = new SdJwtCredentialVerifier(mockFetcher);

        VerificationException exception = assertThrows(
                VerificationException.class,
                () -> verifier.verifyCredential(
                        revocationContext(false), revocationCredential(), presentedSdJwtWithoutStatus()));
        assertTrue(exception.getMessage().contains("Token status verification failed"));
    }

    @Test
    void shouldPass_WhenRevocationEnforcedAndStatusMissingButTolerated() throws Exception {
        var verifier = new SdJwtCredentialVerifier(mockFetcher);

        assertDoesNotThrow(() -> verifier.verifyCredential(
                revocationContext(true), revocationCredential(), presentedSdJwtWithoutStatus()));
    }

    @Test
    void shouldPass_WhenRevocationEnforcedAndStatusValidEvenIfTolerated() throws Exception {
        var verifier = new SdJwtCredentialVerifier(mockFetcher);

        assertDoesNotThrow(() -> verifier.verifyCredential(
                revocationContext(true), revocationCredential(), presentedSdJwtWithStatus(1)));
    }

    @Test
    void shouldFail_WhenRevocationEnforcedAndStatusRevokedEvenIfTolerated() throws Exception {
        var verifier = new SdJwtCredentialVerifier(mockFetcher);

        VerificationException exception = assertThrows(
                VerificationException.class,
                () -> verifier.verifyCredential(
                        revocationContext(true), revocationCredential(), presentedSdJwtWithStatus(0)));
        assertTrue(exception.getMessage().contains("Token status verification failed"));
    }

    private OID4VPAuthenticator.Context revocationContext(boolean allowMissingStatusClaim) throws Exception {
        var authConfig = new AuthenticatorConfigModel();
        authConfig.getConfig().put(ENFORCE_REVOCATION_STATUS_CONFIG, "true");
        authConfig.getConfig().put(VERIFY_ISSUER_CLAIM_CONFIG, "false");
        if (allowMissingStatusClaim) {
            authConfig.getConfig().put(ALLOW_MISSING_STATUS_CLAIM_CONFIG, "true");
        }

        var requestObject = mock(RequestObject.class);
        when(requestObject.getNonce()).thenReturn(NONCE);
        when(requestObject.getClientId()).thenReturn(AUD);

        var authCtx = new AuthorizationContext().setRequestObject(requestObject);

        KeycloakSession session = session();
        var authenticationFlowContext = mock(AuthenticationFlowContext.class);
        when(authenticationFlowContext.getSession()).thenReturn(session);

        return new ContextBuilder()
                .authenticationFlowContext(authenticationFlowContext)
                .authorizationContext(authCtx)
                .authRequirements(new AuthRequirements(authConfig))
                .build();
    }

    /**
     * Self-trust resolution requires a Keycloak session whose keys expose the issuer key that
     * signed the presented credentials; signature verification itself stays real.
     */
    private KeycloakSession session() throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);

        KeycloakContext context = mock(KeycloakContext.class);
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        RealmModel realm = mock(RealmModel.class);
        when(session.getContext()).thenReturn(context);
        when(context.getUri()).thenReturn(uriInfo);
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:8080/auth/"));
        when(context.getRealm()).thenReturn(realm);
        when(realm.getName()).thenReturn("test");

        KeyManager keyManager = mock(KeyManager.class);
        when(session.keys()).thenReturn(keyManager);

        KeyWrapper issuerKey = RSATestUtils.getRsaKeyWrapper(SdJwtVPTestUtils.getKeycloakJwk());
        issuerKey.setStatus(KeyStatus.ACTIVE);
        issuerKey.setUse(KeyUse.SIG);
        when(keyManager.getKeysStream(realm)).thenReturn(Stream.of(issuerKey));

        SignatureProvider signatureProvider = mock(SignatureProvider.class);
        when(session.getProvider(SignatureProvider.class, issuerKey.getAlgorithmOrDefault()))
                .thenReturn(signatureProvider);
        when(signatureProvider.verifier(any(KeyWrapper.class)))
                .thenReturn(new AsymmetricSignatureVerifierContext(issuerKey));

        return session;
    }

    private CredentialRequirement revocationCredential() {
        return new CredentialRequirement()
                .setId("test")
                .setCredentialTypes(List.of(VCT))
                .setClaims(List.of());
    }

    private String presentedSdJwtWithoutStatus() throws Exception {
        return presentSdJwt(SdJwtVPTestUtils.exampleIssuerSignedJwtForTest(
                "https://example.com/realms/test", VCT, "user-id", "test-user"));
    }

    private String presentedSdJwtWithStatus(int statusIdx) throws Exception {
        return presentSdJwt(issuerSignedJwtWithStatus(statusIdx));
    }

    private String presentSdJwt(IssuerSignedJWT issuerSignedJWT) throws Exception {
        JWK issuerJwk = SdJwtVPTestUtils.getKeycloakJwk();
        KeyWrapper issuerKey = RSATestUtils.getRsaKeyWrapper(issuerJwk);
        String sdJwt = SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJWT)
                .withIssuerSigningContext(new AsymmetricSignatureSignerContext(issuerKey))
                .build()
                .toSdJwtString();

        JWK holderKey = SdJwtVPTestUtils.getUserJwk();
        KeyWrapper holderKeyWrapper = ECTestUtils.getEcKeyWrapper(holderKey);
        return SdJwtVP.of(sdJwt)
                .present(
                        null,
                        true,
                        JsonSerialization.mapper.valueToTree(kbJwtClaims()),
                        new ECDSASignatureSignerContext(holderKeyWrapper));
    }

    /**
     * Issuer-signed JWT carrying a status claim at the given index of the IETF 1-bit test vector
     * (idx 0 is INVALID, idx 1 is VALID).
     */
    private IssuerSignedJWT issuerSignedJwtWithStatus(int statusIdx) {
        ObjectNode claimSet = JsonSerialization.mapper.createObjectNode();
        claimSet.put(CLAIM_NAME_VCT, VCT);
        claimSet.put(CLAIM_NAME_EXP, Time.currentTimeSeconds() + SdJwtVPTestUtils.ISSUER_SIGNED_JWT_LIFESPAN_SECS);

        JWK holderJwk = SdJwtVPTestUtils.getUserJwk();
        ObjectNode cnf = JsonSerialization.mapper.createObjectNode();
        cnf.set(CLAIM_NAME_JWK, JsonSerialization.mapper.valueToTree(holderJwk));
        claimSet.set(CLAIM_NAME_CNF, cnf);

        claimSet.set(
                STATUS_FIELD,
                JsonSerialization.mapper.valueToTree(Map.of(
                        STATUS_LIST_FIELD, new ReferencedTokenValidator.StatusInfo(statusIdx, STATUS_LIST_URI))));

        return IssuerSignedJWT.builder()
                .withClaims(
                        claimSet,
                        DisclosureSpec.builder()
                                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA")
                                .build())
                .build();
    }

    private JsonWebToken kbJwtClaims() {
        JsonWebToken kbJwtClaims = new JsonWebToken();
        long currentTime = Time.currentTimeSeconds();
        kbJwtClaims.iat(currentTime);
        kbJwtClaims.exp(currentTime + SdJwtVPTestUtils.KB_JWT_LIFESPAN_SECS);
        kbJwtClaims.getOtherClaims().put(IDToken.NONCE, NONCE);
        kbJwtClaims.getOtherClaims().put(IDToken.AUD, AUD);
        return kbJwtClaims;
    }
}
