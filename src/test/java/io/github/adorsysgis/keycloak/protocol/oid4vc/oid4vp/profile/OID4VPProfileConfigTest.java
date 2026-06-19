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
