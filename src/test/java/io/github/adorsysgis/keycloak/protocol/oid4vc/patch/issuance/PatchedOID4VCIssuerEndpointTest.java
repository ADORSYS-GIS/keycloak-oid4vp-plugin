package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.OpenId4VpConstants.PRESENTATION_VERIFIED_NOTE;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScope.VC_REQUIRES_PRESENTATION_ATTR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
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

    static Stream<Arguments> unsupportedPresentationModes() {
        return Stream.of(
                // No verified-presentation marker at all (covers both a fixed and an any-mode credential).
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), null),
                Arguments.of(List.of(), null),
                // A marker for a mode the credential does not support (nested vs interactive).
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), NESTED_OID4VP_FLOW));
    }

    @ParameterizedTest(name = "gate_shouldBlock when scopeModes={0} and sessionMode={1}")
    @MethodSource("unsupportedPresentationModes")
    public void gate_shouldBlock_WhenSessionLacksSupportedPresentation(
            List<PresentationDuringIssuanceMode> scopeModes, PresentationDuringIssuanceMode sessionMode) {
        CredentialScopeModel scope = mockedScope(scopeModes);
        UserSessionModel session = sessionWithMode(sessionMode);

        assertTrue(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    static Stream<Arguments> supportedPresentationModes() {
        return Stream.of(
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION),
                Arguments.of(List.of(INTERACTIVE_AUTHORIZATION, NESTED_OID4VP_FLOW), INTERACTIVE_AUTHORIZATION),
                // Empty list = accept any mode, so the verified interactive mode is supported.
                Arguments.of(List.of(), INTERACTIVE_AUTHORIZATION));
    }

    @ParameterizedTest(name = "gate_shouldAllow when scopeModes={0} and sessionMode={1}")
    @MethodSource("supportedPresentationModes")
    public void gate_shouldAllow_WhenSessionHasSupportedPresentation(
            List<PresentationDuringIssuanceMode> scopeModes, PresentationDuringIssuanceMode sessionMode) {
        CredentialScopeModel scope = mockedScope(scopeModes);
        UserSessionModel session = sessionWithMode(sessionMode);

        assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    @Test
    public void gate_shouldAllow_whenNotGated() {
        // no requires_presentation attribute configured
        CredentialScopeModel scope = mockedScope(null);
        UserSessionModel session = sessionWithMode(null);

        assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    private static CredentialScopeModel mockedScope(List<PresentationDuringIssuanceMode> modes) {
        CredentialScopeModel scope = mock(CredentialScopeModel.class);
        lenient().when(scope.getProtocol()).thenReturn(OID4VC_PROTOCOL);
        when(scope.getAttribute(VC_REQUIRES_PRESENTATION_ATTR))
                .thenReturn(Optional.ofNullable(modes)
                        .map(l -> l.stream()
                                .map(PatchedOID4VCIssuerEndpointTest::toValue)
                                .collect(Collectors.joining(",")))
                        .orElse(null));
        return scope;
    }

    private static UserSessionModel sessionWithMode(PresentationDuringIssuanceMode mode) {
        UserSessionModel session = mock(UserSessionModel.class);
        lenient().when(session.getNote(PRESENTATION_VERIFIED_NOTE)).thenReturn(toValue(mode));
        return session;
    }

    private static String toValue(PresentationDuringIssuanceMode mode) {
        return Optional.ofNullable(mode)
                .map(PresentationDuringIssuanceMode::getValue)
                .orElse(null);
    }
}
