package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.BindingValueComparator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.ExactBindingValueComparator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.ExactBindingValueComparatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.BindingRule;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

class SdJwtPrimaryBindingTest {

    private static final String PRESENTED_USERNAME = "test-user";

    private final OID4VPAuthenticator authenticator = new OID4VPAuthenticator(Map.of());
    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final CredentialVerifier verifier = mock(CredentialVerifier.class);
    private final UserModel user = mock(UserModel.class);
    private final JsonNode claims = JsonSerialization.mapper.createObjectNode().put("username", PRESENTED_USERNAME);

    @BeforeEach
    void setUp() {
        when(context.getSession()).thenReturn(session);
        when(session.getProvider(BindingValueComparator.class, ExactBindingValueComparatorFactory.PROVIDER_ID))
                .thenReturn(new ExactBindingValueComparator());
        when(verifier.readClaim(claims, "username")).thenReturn(PRESENTED_USERNAME);
    }

    @Test
    void passesWhenClaimMatchesUserAttribute() {
        when(user.getUsername()).thenReturn(PRESENTED_USERNAME);
        assertDoesNotThrow(() -> apply(primaryWithUserAttributeBinding()));
    }

    @Test
    void throwsWhenClaimDoesNotMatchUserAttribute() {
        when(user.getUsername()).thenReturn("someone-else");
        VerificationException error =
                assertThrows(VerificationException.class, () -> apply(primaryWithUserAttributeBinding()));
        assertEquals("Primary credential 'pid' failed binding rule 'claim_equals_user_attribute'", error.getMessage());
    }

    @Test
    void passesWhenNoBindingRules() {
        CredentialRequirement primary = new CredentialRequirement()
                .setId("pid")
                .setRole(CredentialRole.PRIMARY)
                .setBinding(List.of());
        assertDoesNotThrow(() -> apply(primary));
    }

    @Test
    void throwsWhenPrimaryUsesPrimaryClaimRule() {
        CredentialRequirement primary = new CredentialRequirement()
                .setId("pid")
                .setRole(CredentialRole.PRIMARY)
                .setBinding(List.of(new BindingRule()
                        .setType(BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM)
                        .setCredentialClaim("username")
                        .setPrimaryCredentialClaim("username")));
        VerificationException error = assertThrows(VerificationException.class, () -> apply(primary));
        assertEquals(
                "Binding rule 'claim_equals_primary_claim' is not applicable to the primary credential 'pid'",
                error.getMessage());
    }

    private void apply(CredentialRequirement primary) throws VerificationException {
        authenticator.applyBindingRules(context, primary, verifier, claims, null, null, user);
    }

    private static CredentialRequirement primaryWithUserAttributeBinding() {
        return new CredentialRequirement()
                .setId("pid")
                .setRole(CredentialRole.PRIMARY)
                .setBinding(List.of(new BindingRule()
                        .setType(BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE)
                        .setCredentialClaim("username")
                        .setUserAttribute("username")));
    }
}
