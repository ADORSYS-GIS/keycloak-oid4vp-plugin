package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;

import java.util.stream.Stream;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class GuardedCredentialScopeTest {

    @Test
    void supportsEachConfiguredMode() {
        GuardedCredentialScope scope = scope("interactive_authorization, nested_oid4vp_flow", "profile");

        assertTrue(scope.supportsPresentationMode(INTERACTIVE_AUTHORIZATION));
        assertTrue(scope.supportsPresentationMode(NESTED_OID4VP_FLOW));
        assertFalse(scope.supportsPresentationMode((PresentationDuringIssuanceMode) null));
        scope.validateConfiguration();
    }

    @Test
    void blankModeConfigurationAcceptsAnyMode() {
        GuardedCredentialScope scope = scope("  ", "profile");

        assertTrue(scope.requiresPresentation());
        assertTrue(scope.supportsPresentationMode(NESTED_OID4VP_FLOW));
        scope.validateConfiguration();
    }

    @Test
    void acceptsOnlyConfiguredProfile() {
        GuardedCredentialScope scope = scope("interactive_authorization", "profile");

        assertTrue(scope.acceptPresentationProfile("profile"));
        assertFalse(scope.acceptPresentationProfile("other"));
    }

    @Test
    void unconfiguredCredentialDoesNotRequireValidationProfile() {
        GuardedCredentialScope scope = scope(null, null);

        scope.validateConfiguration();
        assertFalse(scope.requiresPresentation());
        // A blank configured profile rejects every presentation — the safe default.
        assertFalse(scope.acceptPresentationProfile("any"));
    }

    @Test
    void rejectsUnsupportedModeWithActionableMessage() {
        GuardedCredentialScope scope = scope("nested_oid4vp_flow, typo", "profile");

        IllegalStateException exception = assertThrows(IllegalStateException.class, scope::validateConfiguration);

        assertEquals(
                "Invalid configuration for OID4VC client scope 'test-scope': "
                        + "'vc.requires_presentation' contains unsupported value 'typo'. "
                        + "Supported values are [interactive_authorization, nested_oid4vp_flow].",
                exception.getMessage());
    }

    @Test
    void requiresProfileWhenPresentationIsGated() {
        GuardedCredentialScope scope = scope("interactive_authorization", " ");

        IllegalStateException exception = assertThrows(IllegalStateException.class, scope::validateConfiguration);

        assertEquals(
                "Invalid configuration for OID4VC client scope 'test-scope': "
                        + "'vc.requires_presentation' requires presentation during issuance "
                        + "but 'vc.presentation_profile_id' is blank or missing. "
                        + "Configure a nonblank presentation profile id.",
                exception.getMessage());
    }

    @Test
    void validatesAllOid4vcScopesInRealm() {
        RealmModel realm = mock(RealmModel.class);
        ClientScopeModel valid = clientScope("interactive_authorization", "profile");
        ClientScopeModel invalid = clientScope("unsupported", "profile");
        when(realm.getClientScopesStream()).thenReturn(Stream.of(valid, invalid));

        IllegalStateException exception =
                assertThrows(IllegalStateException.class, () -> GuardedCredentialScope.validateRealm(realm));

        assertEquals(
                "Invalid configuration for OID4VC client scope 'test-scope': "
                        + "'vc.requires_presentation' contains unsupported value 'unsupported'. "
                        + "Supported values are [interactive_authorization, nested_oid4vp_flow].",
                exception.getMessage());
    }

    private static GuardedCredentialScope scope(String modes, String profile) {
        return GuardedCredentialScope.from(new CredentialScopeModel(clientScope(modes, profile)));
    }

    public static ClientScopeModel clientScope(String modes, String profile) {
        ClientScopeModel clientScope = mock(ClientScopeModel.class);
        when(clientScope.getName()).thenReturn("test-scope");
        when(clientScope.getProtocol()).thenReturn(OID4VC_PROTOCOL);
        when(clientScope.getAttribute(GuardedCredentialScope.VC_REQUIRES_PRESENTATION_ATTR))
                .thenReturn(modes);
        when(clientScope.getAttribute(GuardedCredentialScope.VC_PRESENTATION_PROFILE_ID_ATTR))
                .thenReturn(profile);
        return clientScope;
    }
}
