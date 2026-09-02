package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.util.JsonSerialization;

class OID4VPAuthenticatorIssuerTest {

    private static final String PID_PROVIDER_ID = "PSDDE-PID-PROVIDER-1";

    private final OID4VPAuthenticator authenticator = new OID4VPAuthenticator(Map.of());

    @Test
    void shouldAcceptVerifiedConfiguredPidProvider() {
        assertDoesNotThrow(
                () -> authenticator.enforceConfiguredPrimaryIssuer(primaryMdoc(), verifiedCredential(PID_PROVIDER_ID)));
    }

    @Test
    void shouldRejectDifferentVerifiedPidProvider() {
        VerificationException error = assertThrows(
                VerificationException.class,
                () -> authenticator.enforceConfiguredPrimaryIssuer(
                        primaryMdoc(), verifiedCredential("PSDDE-OTHER-PROVIDER")));

        assertEquals("Verified mDoc issuer does not match the configured PID Provider", error.getMessage());
    }

    @Test
    void shouldRejectMissingVerifiedPidProvider() {
        assertThrows(
                VerificationException.class,
                () -> authenticator.enforceConfiguredPrimaryIssuer(primaryMdoc(), verifiedCredential(null)));
    }

    private CredentialRequirement primaryMdoc() {
        TrustPolicy trust =
                new TrustPolicy().setType(TrustPolicy.EUDI_PID_TRUST_LIST).setIssuer(PID_PROVIDER_ID);
        return new CredentialRequirement()
                .setId("pid")
                .setRole(CredentialRole.PRIMARY)
                .setTrust(List.of(trust));
    }

    private VerifiedCredential verifiedCredential(String issuer) {
        return new VerifiedCredential(
                issuer, JsonSerialization.mapper.createObjectNode().put("sub", "user-id"));
    }
}
