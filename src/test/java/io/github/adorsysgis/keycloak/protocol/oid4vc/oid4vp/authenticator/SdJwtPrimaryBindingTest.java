package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.BindingValueComparator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.ExactBindingValueComparator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.ExactBindingValueComparatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.BindingRule;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.mockito.Mockito;

/**
 * Unit tests for the configurable identity gate that binds the presented primary credential (e.g. a
 * PID during OID4VCI presentation during issuance) to the authenticated Keycloak user through the
 * profile's {@link BindingRule}s. This replaces the former hard-coded PID matcher SPI.
 */
class SdJwtPrimaryBindingTest {

    private static final String VCT = "https://credentials.example.com/identity_credential";
    private static final String PRESENTED_USERNAME = "test-user";

    // The verifier only needs the session to resolve the pluggable value comparator; the default
    // "exact" strategy is stubbed in. Consumer/token-status are untouched for primary binding rules.
    private final KeycloakSession session = mockSessionWithExactComparator();
    private final SdJwtSupportingCredentialVerifier verifier =
            new SdJwtSupportingCredentialVerifier(session, null, null);

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(SdJwtPrimaryBindingTest.class.getClassLoader());
    }

    private static KeycloakSession mockSessionWithExactComparator() {
        KeycloakSession session = mock(KeycloakSession.class);
        Mockito.lenient()
                .when(session.getProvider(BindingValueComparator.class, ExactBindingValueComparatorFactory.PROVIDER_ID))
                .thenReturn(new ExactBindingValueComparator());
        return session;
    }

    @Test
    @DisplayName("passes when the presented claim equals the configured user attribute")
    void passes_WhenClaimMatchesUserAttribute() {
        CredentialRequirement primary = primaryWithUserAttributeBinding();
        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn(PRESENTED_USERNAME);

        assertDoesNotThrow(() -> verifier.verifyPrimaryBinding(primary, issuerSignedSdJwt(), user));
    }

    @Test
    @DisplayName("throws when the presented claim does not match the configured user attribute")
    void throws_WhenClaimDoesNotMatchUserAttribute() {
        CredentialRequirement primary = primaryWithUserAttributeBinding();
        UserModel user = mock(UserModel.class);
        when(user.getUsername()).thenReturn("someone-else");

        assertThrows(
                VerificationException.class, () -> verifier.verifyPrimaryBinding(primary, issuerSignedSdJwt(), user));
    }

    @Test
    @DisplayName("passes when the primary credential defines no binding rules")
    void passes_WhenNoBindingRules() {
        CredentialRequirement primary = new CredentialRequirement()
                .setId("pid")
                .setRole(CredentialRole.PRIMARY)
                .setBinding(List.of());

        assertDoesNotThrow(() -> verifier.verifyPrimaryBinding(primary, issuerSignedSdJwt(), mock(UserModel.class)));
    }

    @Test
    @DisplayName("throws when a primary credential is misconfigured with a primary-claim binding rule")
    void throws_WhenPrimaryUsesPrimaryClaimRule() {
        CredentialRequirement primary = new CredentialRequirement()
                .setId("pid")
                .setRole(CredentialRole.PRIMARY)
                .setBinding(List.of(new BindingRule()
                        .setType(BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM)
                        .setCredentialClaim("username")
                        .setPrimaryCredentialClaim("username")));

        assertThrows(
                VerificationException.class,
                () -> verifier.verifyPrimaryBinding(primary, issuerSignedSdJwt(), mock(UserModel.class)));
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

    private static SdJwtVP issuerSignedSdJwt() throws Exception {
        JWK issuerJwk = SdJwtVPTestUtils.getKeycloakJwk();
        KeyWrapper issuerKey = RSATestUtils.getRsaKeyWrapper(issuerJwk);
        String sdJwt = SdJwt.builder()
                .withIssuerSignedJwt(SdJwtVPTestUtils.exampleIssuerSignedJwtForTest(
                        "https://example.com/realms/test", VCT, "user-id", PRESENTED_USERNAME))
                .withIssuerSigningContext(new AsymmetricSignatureSignerContext(issuerKey))
                .build()
                .toSdJwtString();
        return SdJwtVP.of(sdJwt);
    }
}
