package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.HardenedCredentialScope.VC_REQUIRES_PRESENTATION_ATTR;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.OpenId4VpConstants.PRESENTATION_VERIFIED_NOTE;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
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

    @Test
    public void gate_shouldBlock_whenGatedAndNoPresentationMarker() {
        CredentialScopeModel scope = gatedScope(true);
        UserSessionModel session = sessionWithMode(null); // no presentation mode recorded

        assertTrue(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    @Test
    public void gate_shouldBlock_whenGatedAndMarkerFalse() {
        CredentialScopeModel scope = gatedScope(true);
        UserSessionModel session = sessionWithMode("false"); // no valid mode recorded

        assertTrue(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    @Test
    public void gate_shouldBlock_whenGatedAndSessionIsNull() {
        // Pre-authorized code path: access token bound to a session that never did a presentation.
        CredentialScopeModel scope = gatedScope(true);

        assertTrue(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, null));
    }

    @Test
    public void gate_shouldAllow_whenGatedAndPresentationVerified() {
        CredentialScopeModel scope = gatedScope(true);
        UserSessionModel session = sessionWithMode(INTERACTIVE_AUTHORIZATION.wireValue());

        assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    @Test
    public void gate_shouldAllow_whenNotGated() {
        CredentialScopeModel scope = gatedScope(false); // attribute "false"
        UserSessionModel session = sessionWithMode(null);

        assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    @Test
    public void gate_shouldAllow_whenAttributeAbsent() {
        CredentialScopeModel scope = mockedScope();
        when(scope.getAttribute(VC_REQUIRES_PRESENTATION_ATTR)).thenReturn(null); // attribute not configured
        UserSessionModel session = sessionWithMode(null);

        assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
    }

    private static CredentialScopeModel gatedScope(boolean requiresPresentation) {
        CredentialScopeModel scope = mockedScope();
        when(scope.getAttribute(VC_REQUIRES_PRESENTATION_ATTR)).thenReturn(String.valueOf(requiresPresentation));
        return scope;
    }

    /**
     * The {@code CredentialScopeModel} constructor asserts the scope's protocol is {@code oid4vc}, so a
     * mock must advertise that protocol.
     */
    private static CredentialScopeModel mockedScope() {
        CredentialScopeModel scope = mock(CredentialScopeModel.class);
        lenient().when(scope.getProtocol()).thenReturn(OID4VC_PROTOCOL);
        return scope;
    }

    private static UserSessionModel sessionWithMode(String modeValue) {
        UserSessionModel session = mock(UserSessionModel.class);
        lenient().when(session.getNote(PRESENTATION_VERIFIED_NOTE)).thenReturn(modeValue);
        return session;
    }
}
