package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.PROFILES_CONFIG;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

public class OID4VPProfileConfigTest {

    @Test
    void shouldParseConfiguredProfiles() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "dual",
                    "displayCta": { "en": "Sign in with two credentials" },
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "vct": ["main-vct"],
                        "claims": ["sub", "username"]
                      },
                      {
                        "id": "supporting",
                        "role": "supporting",
                        "vct": ["supporting-vct"],
                        "claims": ["username"],
                        "binding": [
                          {
                            "type": "claim_equals_primary_claim",
                            "credentialClaim": "username",
                            "primaryCredentialClaim": "username"
                          }
                        ]
                      }
                    ]
                  }
                ]
                """));

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(null, config);

        AuthenticationProfile profile = profileConfig.getProfile("dual");
        assertEquals("dual", profile.getId());
        assertEquals("Sign in with two credentials", profile.getDisplayCta(java.util.Locale.ENGLISH));
        assertEquals(2, profile.getCredentials().size());
    }

    @Test
    void shouldParseEudiPidTrustListPolicy() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "dual-pid",
                    "credentials": [
                      { "id": "primary", "role": "primary", "vct": ["tax-advisor"], "claims": ["sub"] },
                      {
                        "id": "pid",
                        "role": "supporting",
                        "vct": ["urn:eudi:pid:de:1"],
                        "claims": ["given_name", "family_name"],
                        "trust": [
                          {
                            "type": "eudi_pid_trust_list",
                            "trustListUrl": "https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt",
                            "trustListSigningCertificate": "MIICDDCCAXOgAwIBAgIU",
                            "serviceType": "http://uri.etsi.org/19602/SvcType/PID/Issuance",
                            "issuer": "https://preprod.pid-provider.bundesdruckerei.de"
                          }
                        ]
                      }
                    ]
                  }
                ]
                """));

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(null, config);

        TrustPolicy trustPolicy = profileConfig
                .getProfile("dual-pid")
                .getCredentials()
                .get(1)
                .getTrust()
                .get(0);
        assertEquals(TrustPolicy.EUDI_PID_TRUST_LIST, trustPolicy.getType());
        assertEquals(
                "https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt",
                trustPolicy.getTrustListUrl());
        assertEquals("MIICDDCCAXOgAwIBAgIU", trustPolicy.getTrustListSigningCertificate());
        assertEquals("http://uri.etsi.org/19602/SvcType/PID/Issuance", trustPolicy.getServiceType());
        assertEquals("https://preprod.pid-provider.bundesdruckerei.de", trustPolicy.getIssuer());
    }

    @Test
    void shouldRejectProfilesWithoutExactlyOnePrimaryCredential() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "broken",
                    "credentials": [
                      { "id": "one", "role": "supporting", "vct": ["vct"], "claims": ["username"] }
                    ]
                  }
                ]
                """));

        assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(null, config));
    }
}
