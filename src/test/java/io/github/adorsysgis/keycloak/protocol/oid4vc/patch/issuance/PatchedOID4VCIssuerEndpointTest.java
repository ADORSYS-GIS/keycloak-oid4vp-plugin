package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.OpenId4VpConstants.PRESENTATION_VERIFIED_NOTE;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScopeTest.clientScope;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationVerifiedNote;
import jakarta.ws.rs.BadRequestException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCAuthorizationDetailsProcessor;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.ErrorType;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessor;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.util.JsonSerialization;

public class PatchedOID4VCIssuerEndpointTest {

    @Test
    public void testPatchWalletRequest() throws Exception {
        // Case 1: wallet sends credential_configuration_id only
        String payload = "{\"credential_configuration_id\": \"my-config\"}";
        String patched = PatchedOID4VCIssuerEndpoint.patchWalletRequest(payload);

        CredentialRequest req = JsonSerialization.readValue(patched, CredentialRequest.class);
        assertEquals("my-config", req.getCredentialIdentifier());
        assertNull(req.getCredentialConfigurationId());

        // Case 2: wallet sends both (already correct or following some other logic)
        payload = "{\"credential_configuration_id\": \"my-config\", \"credential_identifier\": \"my-id\"}";
        patched = PatchedOID4VCIssuerEndpoint.patchWalletRequest(payload);
        assertEquals(payload, patched);

        // Case 3: wallet sends credential_identifier only (already correct)
        payload = "{\"credential_identifier\": \"my-id\"}";
        patched = PatchedOID4VCIssuerEndpoint.patchWalletRequest(payload);
        assertEquals(payload, patched);

        // Case 4: null/empty
        assertNull(PatchedOID4VCIssuerEndpoint.patchWalletRequest(null));
        assertEquals("", PatchedOID4VCIssuerEndpoint.patchWalletRequest(""));

        // Case 5: invalid JSON (should be forwarded as-is)
        String invalidJson = "{\"invalid\": ";
        assertEquals(invalidJson, PatchedOID4VCIssuerEndpoint.patchWalletRequest(invalidJson));

        // Case 6: whitespace-only payload (should be returned unchanged)
        String whitespace = "   ";
        assertEquals(whitespace, PatchedOID4VCIssuerEndpoint.patchWalletRequest(whitespace));
    }

    static Stream<Arguments> unsupportedPresentations() {
        return Stream.of(
                // No verified-presentation marker on the session at all.
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), null, null, null),
                // A session verified via a mode the credential does not allow.
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), NESTED_OID4VP_FLOW, null, null),
                // A credential that accepts several modes still blocks a session with no marker.
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION, NESTED_OID4VP_FLOW), null, null, null),
                Arguments.of(List.of(), null, null, null),
                // A supported mode does not save a presentation bound to another authentication profile.
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION, "enforced", "other"),
                // A supported mode without any bound profile fails when a profile is enforced.
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION, "enforced", null));
    }

    @ParameterizedTest(
            name = "gate_shouldBlock when scopeModes={0}, sessionMode={1}, scopeProfile={2}, noteProfile={3}")
    @MethodSource("unsupportedPresentations")
    public void gate_shouldBlock_WhenSessionLacksSupportedPresentation(
            List<PresentationDuringIssuanceMode> scopeModes,
            PresentationDuringIssuanceMode sessionMode,
            String scopeProfileId,
            String noteProfileId) {
        CredentialScopeModel scope = mockedScope(scopeModes, scopeProfileId);
        UserSessionModel session = sessionWithNote(sessionMode, noteProfileId);

        assertTrue(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    static Stream<Arguments> supportedPresentations() {
        return Stream.of(
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION, "enforced", "enforced"),
                Arguments.of(
                        List.of(INTERACTIVE_AUTHORIZATION, NESTED_OID4VP_FLOW), INTERACTIVE_AUTHORIZATION, "enforced", "enforced"),
                // Empty list = accept any mode, so the verified interactive mode is supported.
                Arguments.of(List.of(), INTERACTIVE_AUTHORIZATION, "enforced", "enforced"),
                // The presentation matches the concrete authentication profile enforced by the credential.
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION, "enforced", "enforced"));
    }

    @ParameterizedTest(
            name = "gate_shouldAllow when scopeModes={0}, sessionMode={1}, scopeProfile={2}, noteProfile={3}")
    @MethodSource("supportedPresentations")
    public void gate_shouldAllow_WhenSessionHasSupportedPresentation(
            List<PresentationDuringIssuanceMode> scopeModes,
            PresentationDuringIssuanceMode sessionMode,
            String scopeProfileId,
            String noteProfileId) {
        CredentialScopeModel scope = mockedScope(scopeModes, scopeProfileId);
        UserSessionModel session = sessionWithNote(sessionMode, noteProfileId);

        assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    @Test
    public void gate_shouldAllow_whenNotGated() {
        // no requires_presentation attribute configured
        CredentialScopeModel scope = mockedScope(null, null);
        UserSessionModel session = sessionWithNote(null, null);

        assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    @Test
    public void resolve_shouldRejectImmediately_whenAccessTokenGrantsMultipleCredentials() {
        MockPatchedOID4VCIssuerEndpoint endpoint = new MockPatchedOID4VCIssuerEndpoint();

        OID4VCAuthorizationDetailsProcessor processor = mock(OID4VCAuthorizationDetailsProcessor.class);
        when(processor.getSupportedAuthorizationDetails(any()))
                .thenReturn(List.of(new OID4VCAuthorizationDetail(), new OID4VCAuthorizationDetail()));
        when(endpoint.getSession().getProvider(AuthorizationDetailsProcessor.class, OPENID_CREDENTIAL))
                .thenReturn(processor);

        AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
        when(authResult.token()).thenReturn(mock(AccessToken.class));
        EventBuilder eventBuilder = endpoint.getEventBuilder();

        BadRequestException ex = assertThrows(
                BadRequestException.class,
                () -> endpoint.resolveRequestedCredentialConfigurationId(authResult, eventBuilder));

        OAuth2ErrorRepresentation error =
                (OAuth2ErrorRepresentation) ex.getResponse().getEntity();
        assertEquals(ErrorType.INVALID_CREDENTIAL_REQUEST.getValue(), error.getError());
        assertTrue(error.getErrorDescription().contains("Multiple authorization_details not supported"));
        verify(eventBuilder).error(ErrorType.INVALID_CREDENTIAL_REQUEST.getValue());
    }

    public static CredentialScopeModel mockedScope(List<PresentationDuringIssuanceMode> modes, String profileId) {
        return new CredentialScopeModel(clientScope(
                Optional.ofNullable(modes)
                        .map(values -> values.stream()
                                .map(v -> v != null ? v.getValue() : null)
                                .collect(Collectors.joining(",")))
                        .orElse(null),
                profileId));
    }

    private static UserSessionModel sessionWithNote(PresentationDuringIssuanceMode mode, String profileId) {
        UserSessionModel session = mock(UserSessionModel.class);
        String note = mode == null
                ? null
                : PresentationVerifiedNote.of(mode, profileId).toJson();
        lenient().when(session.getNote(PRESENTATION_VERIFIED_NOTE)).thenReturn(note);
        return session;
    }

    /**
     * Test double that extends {@link PatchedOID4VCIssuerEndpoint} with a mocked {@link KeycloakSession}.
     */
    static class MockPatchedOID4VCIssuerEndpoint extends PatchedOID4VCIssuerEndpoint {

        MockPatchedOID4VCIssuerEndpoint() {
            super(stubSession());
        }

        static KeycloakSession stubSession() {
            KeycloakSessionFactory factory = mock(KeycloakSessionFactory.class);
            lenient()
                    .when(factory.getProviderFactoriesStream(CredentialBuilder.class))
                    .thenReturn(Stream.of());

            KeycloakContext context = mock(KeycloakContext.class);
            lenient().when(context.getRealm()).thenReturn(mock(RealmModel.class));

            KeycloakSession session = mock(KeycloakSession.class);
            lenient().when(session.getKeycloakSessionFactory()).thenReturn(factory);
            lenient().when(session.getContext()).thenReturn(context);
            return session;
        }

        public KeycloakSession getSession() {
            return keycloakSession;
        }

        public EventBuilder getEventBuilder() {
            EventBuilder eventBuilder = mock(EventBuilder.class);
            when(eventBuilder.detail(anyString(), anyString())).thenReturn(eventBuilder);
            return eventBuilder;
        }
    }
}
