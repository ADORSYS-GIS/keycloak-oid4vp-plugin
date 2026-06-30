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
                        "credentialTypes": ["main-vct"],
                        "claims": ["sub", "username"]
                      },
                      {
                        "id": "supporting",
                        "role": "supporting",
                        "credentialTypes": ["supporting-vct"],
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
        assertEquals(
                "main-vct", profile.getPrimaryCredential().getCredentialTypes().getFirst());
    }

    @Test
    void shouldResolveDefaultToFirstConfiguredProfileWhenNoExplicitDefaultExists() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "pid-login",
                    "credentials": [
                      {
                        "id": "pid",
                        "role": "primary",
                        "credentialTypes": ["urn:eudi:pid:1"],
                        "claims": ["sub", "username"]
                      }
                    ]
                  }
                ]
                """));

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(null, config);

        assertEquals("pid-login", profileConfig.getProfile(null).getId());
        assertEquals(
                "pid-login",
                profileConfig
                        .getProfile(AuthenticationProfile.DEFAULT_PROFILE_ID)
                        .getId());
    }

    @Test
    void shouldRejectUnknownConfiguredProfileId() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "pid-login",
                    "credentials": [
                      {
                        "id": "pid",
                        "role": "primary",
                        "credentialTypes": ["urn:eudi:pid:1"],
                        "claims": ["sub", "username"]
                      }
                    ]
                  }
                ]
                """));

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(null, config);

        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> profileConfig.getProfile("typo"));
        assertEquals("Unknown OpenID4VP profile: typo", error.getMessage());
    }

    @Test
    void shouldParseEudiPidTrustListPolicy() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "dual-pid",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "credentialTypes": ["tax-advisor"],
                        "claims": ["sub", "username"]
                      },
                      {
                        "id": "pid",
                        "role": "supporting",
                        "credentialTypes": ["https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0"],
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
                .getCredential("pid")
                .getTrust()
                .getFirst();
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
                      { "id": "one", "role": "supporting", "credentialTypes": ["vct"], "claims": ["username"] }
                    ]
                  }
                ]
                """));

        IllegalStateException error =
                assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(null, config));
        assertEquals("OpenID4VP profile must have exactly one primary credential: broken", error.getMessage());
    }

    @Test
    void shouldRejectDuplicateCredentialIds() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "broken",
                    "credentials": [
                      { "id": "same-id", "role": "primary", "credentialTypes": ["main-vct"], "claims": ["sub", "username"] },
                      { "id": "same-id", "role": "supporting", "credentialTypes": ["supporting-vct"], "claims": ["username"] }
                    ]
                  }
                ]
                """));

        IllegalStateException error =
                assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(null, config));
        assertEquals("OpenID4VP credential ids must be unique in profile: broken", error.getMessage());
    }
}
