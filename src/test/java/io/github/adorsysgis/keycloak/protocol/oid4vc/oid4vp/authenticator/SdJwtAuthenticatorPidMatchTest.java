package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.matcher.PidData;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.matcher.PidMatcherProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Unit tests for the PID-match identity gate. Verifies that matching applies exclusively to the
 * presentation-during-issuance flow and that the {@code pidMatchRequired} flag fails closed when no
 * matcher provider is deployed.
 */
class SdJwtAuthenticatorPidMatchTest {

    private static final String VCT = "https://credentials.example.com/identity_credential";

    private final SdJwtAuthenticator authenticator = new SdJwtAuthenticator(mock(StatusListJwtFetcher.class));

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(SdJwtAuthenticatorPidMatchTest.class.getClassLoader());
    }

    @Test
    @DisplayName("skips matching for a standalone login (not presentation during issuance)")
    void skipsMatch_WhenNotPresentationDuringIssuance() throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);
        AuthenticationFlowContext context = context(null, session, null);

        assertTrue(authenticator.enforcePidMatch(context, issuerSignedSdJwt(), mock(UserModel.class)));
        // The matcher is never resolved outside the issuance flow.
        verify(session, never()).getProvider(PidMatcherProvider.class);
    }

    @Test
    @DisplayName("skips matching during issuance when no matcher is deployed and not required")
    void skips_WhenMatcherAbsentAndNotRequired() throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getProvider(PidMatcherProvider.class)).thenReturn(null);
        AuthenticationFlowContext context = context("true", session, null);

        assertTrue(authenticator.enforcePidMatch(context, issuerSignedSdJwt(), mock(UserModel.class)));
        verify(context, never()).failure(any(), any());
    }

    @Test
    @DisplayName("fails closed during issuance when matching is required but no matcher is deployed")
    void failsClosed_WhenMatcherAbsentAndRequired() throws Exception {
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getProvider(PidMatcherProvider.class)).thenReturn(null);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(config.getConfig()).thenReturn(Map.of(SdJwtAuthenticatorFactory.PID_MATCH_REQUIRED_CONFIG, "true"));
        AuthenticationFlowContext context = context("true", session, config);

        assertFalse(authenticator.enforcePidMatch(context, issuerSignedSdJwt(), mock(UserModel.class)));
        verify(context).failure(any(), any());
    }

    @Test
    @DisplayName("rejects the presentation when the matcher reports a mismatch")
    void rejects_WhenMatcherReportsMismatch() throws Exception {
        PidMatcherProvider matcher = mock(PidMatcherProvider.class);
        when(matcher.findMismatchedAttributes(any(PidData.class), any(PidData.class)))
                .thenReturn(List.of("SURNAME"));
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getProvider(PidMatcherProvider.class)).thenReturn(matcher);
        AuthenticationFlowContext context = context("true", session, null);

        assertFalse(authenticator.enforcePidMatch(context, issuerSignedSdJwt(), mock(UserModel.class)));
        verify(context).failure(any(), any());
    }

    @Test
    @DisplayName("continues when the matcher reports a full match")
    void continues_WhenMatcherReportsMatch() throws Exception {
        PidMatcherProvider matcher = mock(PidMatcherProvider.class);
        when(matcher.findMismatchedAttributes(any(PidData.class), any(PidData.class)))
                .thenReturn(List.of());
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getProvider(PidMatcherProvider.class)).thenReturn(matcher);
        AuthenticationFlowContext context = context("true", session, null);

        assertTrue(authenticator.enforcePidMatch(context, issuerSignedSdJwt(), mock(UserModel.class)));
        verify(context, never()).failure(any(), any());
    }

    private AuthenticationFlowContext context(
            String issuanceMarker, KeycloakSession session, AuthenticatorConfigModel config) {
        RootAuthenticationSessionModel parent = mock(RootAuthenticationSessionModel.class);
        when(parent.getId()).thenReturn("root-session-id");
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(authSession.getParentSession()).thenReturn(parent);
        when(authSession.getTabId()).thenReturn("tab-id");
        when(authSession.getAuthNote(SdJwtAuthenticator.PRESENTATION_DURING_ISSUANCE_KEY))
                .thenReturn(issuanceMarker);

        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getSession()).thenReturn(session);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        return context;
    }

    private static SdJwtVP issuerSignedSdJwt() throws Exception {
        JWK issuerJwk = SdJwtVPTestUtils.getKeycloakJwk();
        KeyWrapper issuerKey = RSATestUtils.getRsaKeyWrapper(issuerJwk);
        String sdJwt = SdJwt.builder()
                .withIssuerSignedJwt(SdJwtVPTestUtils.exampleIssuerSignedJwtForTest(
                        "https://example.com/realms/test", VCT, "user-id", "test-user"))
                .withIssuerSigningContext(new AsymmetricSignatureSignerContext(issuerKey))
                .build()
                .toSdJwtString();
        return SdJwtVP.of(sdJwt);
    }
}
