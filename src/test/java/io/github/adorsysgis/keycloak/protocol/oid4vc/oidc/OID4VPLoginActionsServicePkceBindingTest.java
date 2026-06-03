package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Unit tests for wrapped-flow PKCE continuity checks at {@code oid4vp-auth-login}.
 */
class OID4VPLoginActionsServicePkceBindingTest {

    private static final String CHALLENGE_A = "challenge-a";
    private static final String CHALLENGE_B = "challenge-b";
    private static final String S256 = OAuth2Constants.PKCE_METHOD_S256;

    @Test
    void acceptsMatchingNonBlankPkceNotes() {
        AuthenticationSessionModel parent = mock(AuthenticationSessionModel.class);
        AuthenticatedClientSessionModel issued = mock(AuthenticatedClientSessionModel.class);
        stubPkce(parent, CHALLENGE_A, S256);
        stubPkce(issued, CHALLENGE_A, S256);

        assertTrue(OID4VPLoginActionsService.verifyWrappedFlowPkceBinding(parent, issued));
    }

    @Test
    void rejectsWhenParentPkceMissing() {
        AuthenticationSessionModel parent = mock(AuthenticationSessionModel.class);
        AuthenticatedClientSessionModel issued = mock(AuthenticatedClientSessionModel.class);
        stubPkce(parent, null, null);
        stubPkce(issued, CHALLENGE_A, S256);

        assertFalse(OID4VPLoginActionsService.verifyWrappedFlowPkceBinding(parent, issued));
    }

    @Test
    void rejectsWhenIssuedCodePkceMissing() {
        AuthenticationSessionModel parent = mock(AuthenticationSessionModel.class);
        AuthenticatedClientSessionModel issued = mock(AuthenticatedClientSessionModel.class);
        stubPkce(parent, CHALLENGE_A, S256);
        stubPkce(issued, null, null);

        assertFalse(OID4VPLoginActionsService.verifyWrappedFlowPkceBinding(parent, issued));
    }

    @Test
    void rejectsWhenPkceChallengeMismatch() {
        AuthenticationSessionModel parent = mock(AuthenticationSessionModel.class);
        AuthenticatedClientSessionModel issued = mock(AuthenticatedClientSessionModel.class);
        stubPkce(parent, CHALLENGE_A, S256);
        stubPkce(issued, CHALLENGE_B, S256);

        assertFalse(OID4VPLoginActionsService.verifyWrappedFlowPkceBinding(parent, issued));
    }

    private static void stubPkce(Object session, String challenge, String method) {
        if (session instanceof AuthenticationSessionModel authSession) {
            when(authSession.getClientNote(OAuth2Constants.CODE_CHALLENGE)).thenReturn(challenge);
            when(authSession.getClientNote(OAuth2Constants.CODE_CHALLENGE_METHOD))
                    .thenReturn(method);
        } else if (session instanceof AuthenticatedClientSessionModel clientSession) {
            when(clientSession.getNote(OAuth2Constants.CODE_CHALLENGE)).thenReturn(challenge);
            when(clientSession.getNote(OAuth2Constants.CODE_CHALLENGE_METHOD)).thenReturn(method);
        } else {
            throw new IllegalArgumentException("Unsupported session mock type");
        }
    }
}
