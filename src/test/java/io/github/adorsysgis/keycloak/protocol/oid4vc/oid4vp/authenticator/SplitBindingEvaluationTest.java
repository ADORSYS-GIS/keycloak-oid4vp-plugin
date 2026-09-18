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
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.BindingRule;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.VerificationException;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

/**
 * Covers the split binding evaluation: claim-to-primary-claim rules need no user, and
 * claim-to-user-attribute rules evaluate against staged import attributes exactly like they do
 * against a resolved user.
 */
class SplitBindingEvaluationTest {

    private final OID4VPAuthenticator authenticator = new OID4VPAuthenticator(Map.of());
    private final AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final CredentialVerifier primaryVerifier = mock(CredentialVerifier.class);
    private final CredentialVerifier supportingVerifier = mock(CredentialVerifier.class);
    private final JsonNode primaryClaims =
            JsonSerialization.mapper.createObjectNode().put("family_name", "Lovelace");
    private final JsonNode supportingClaims =
            JsonSerialization.mapper.createObjectNode().put("family_name", "Lovelace");

    @BeforeEach
    void setUp() {
        when(context.getSession()).thenReturn(session);
        when(session.getProvider(BindingValueComparator.class, ExactBindingValueComparatorFactory.PROVIDER_ID))
                .thenReturn(new ExactBindingValueComparator());
        when(primaryVerifier.readClaim(primaryClaims, "family_name")).thenReturn("Lovelace");
        when(supportingVerifier.readClaim(supportingClaims, "family_name")).thenReturn("Lovelace");
    }

    @Test
    void primaryClaimBindingNeedsNoUser() {
        OID4VPAuthenticator.Context ctx = context(supportingWithPrimaryClaimBinding());

        assertDoesNotThrow(() -> authenticator.applyPrimaryClaimBindings(
                ctx, primaryClaims, supportingWithPrimaryClaimBinding(), supportingClaims));
    }

    @Test
    void primaryClaimMismatchFailsWithoutUser() {
        OID4VPAuthenticator.Context ctx = context(supportingWithPrimaryClaimBinding());
        JsonNode otherClaims = JsonSerialization.mapper.createObjectNode().put("family_name", "Hopper");
        when(supportingVerifier.readClaim(otherClaims, "family_name")).thenReturn("Hopper");

        VerificationException error = assertThrows(
                VerificationException.class,
                () -> authenticator.applyPrimaryClaimBindings(
                        ctx, primaryClaims, supportingWithPrimaryClaimBinding(), otherClaims));
        assertEquals("Credential 'sup' failed binding rule 'claim_equals_primary_claim'", error.getMessage());
    }

    @Test
    void splitMethodsIgnoreEachOthersRuleTypes() {
        OID4VPAuthenticator.Context ctx = context(supportingWithBothRuleTypes());

        assertDoesNotThrow(() -> authenticator.applyPrimaryClaimBindings(
                ctx, primaryClaims, supportingWithBothRuleTypes(), supportingClaims));
        assertDoesNotThrow(() -> authenticator.applyUserAttributeBindings(
                ctx, supportingWithBothRuleTypes(), supportingClaims, attribute -> "Lovelace"));
    }

    @Test
    void userAttributeBindingEvaluatesAgainstStagedAttributes() {
        OID4VPAuthenticator.Context ctx = context(supportingWithUserAttributeBinding());
        BrokeredIdentityContext staged = stagedContext("Lovelace");

        assertDoesNotThrow(() -> authenticator.applyUserAttributeBindings(
                ctx,
                supportingWithUserAttributeBinding(),
                supportingClaims,
                attribute -> OID4VPAuthenticator.readStagedUserAttribute(staged, attribute)));
    }

    @Test
    void stagedMismatchFailsLikeUserMismatch() {
        OID4VPAuthenticator.Context ctx = context(supportingWithUserAttributeBinding());
        BrokeredIdentityContext staged = stagedContext("Hopper");

        VerificationException error = assertThrows(
                VerificationException.class,
                () -> authenticator.applyUserAttributeBindings(
                        ctx,
                        supportingWithUserAttributeBinding(),
                        supportingClaims,
                        attribute -> OID4VPAuthenticator.readStagedUserAttribute(staged, attribute)));
        assertEquals("Credential 'sup' failed binding rule 'claim_equals_user_attribute'", error.getMessage());
    }

    private OID4VPAuthenticator.Context context(CredentialRequirement supporting) {
        CredentialRequirement primary = new CredentialRequirement().setId("pid").setRole(CredentialRole.PRIMARY);
        AuthenticationProfile profile =
                new AuthenticationProfile().setId("default").setCredentials(List.of(primary, supporting));

        return new ContextBuilder()
                .id("id")
                .authenticationFlowContext(context)
                .authenticationProfile(profile)
                .presentedToken("pid", "primary-token")
                .credentialVerifier("pid", primaryVerifier)
                .credentialVerifier("sup", supportingVerifier)
                .build();
    }

    private static CredentialRequirement supportingWithPrimaryClaimBinding() {
        return new CredentialRequirement()
                .setId("sup")
                .setRole(CredentialRole.SUPPORTING)
                .setBinding(List.of(new BindingRule()
                        .setType(BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM)
                        .setCredentialClaim("family_name")
                        .setPrimaryCredentialClaim("family_name")));
    }

    private static CredentialRequirement supportingWithUserAttributeBinding() {
        return new CredentialRequirement()
                .setId("sup")
                .setRole(CredentialRole.SUPPORTING)
                .setBinding(List.of(new BindingRule()
                        .setType(BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE)
                        .setCredentialClaim("family_name")
                        .setUserAttribute("family_name")));
    }

    private static CredentialRequirement supportingWithBothRuleTypes() {
        return new CredentialRequirement()
                .setId("sup")
                .setRole(CredentialRole.SUPPORTING)
                .setBinding(List.of(
                        new BindingRule()
                                .setType(BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM)
                                .setCredentialClaim("family_name")
                                .setPrimaryCredentialClaim("family_name"),
                        new BindingRule()
                                .setType(BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE)
                                .setCredentialClaim("family_name")
                                .setUserAttribute("family_name")));
    }

    private static BrokeredIdentityContext stagedContext(String lastName) {
        IdentityProviderModel idp = new IdentityProviderModel();
        idp.setAlias("oid4vp-import");
        idp.setEnabled(true);
        BrokeredIdentityContext staged = new BrokeredIdentityContext("external-id", idp);
        staged.setLastName(lastName);
        return staged;
    }
}
