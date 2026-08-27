package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.PROFILES_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.TRANSACTION_DATA_CONFIG;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import java.util.HashMap;
import java.util.List;
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

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(config);

        AuthenticationProfile profile = profileConfig.getProfile("dual");
        assertEquals("dual", profile.getId());
        assertEquals("Sign in with two credentials", profile.getDisplayCta(java.util.Locale.ENGLISH));
        assertEquals(2, profile.getCredentials().size());
        assertEquals(
                "main-vct", profile.getPrimaryCredential().getCredentialTypes().getFirst());
    }

    @Test
    void shouldParseCredentialGroups() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "grouped",
                    "credentials": [
                      { "id": "passport", "role": "primary", "credentialTypes": ["passport-vct"], "claims": ["sub", "username"] },
                      { "id": "national-id", "role": "primary", "credentialTypes": ["national-id-vct"], "claims": ["sub", "username"] },
                      { "id": "pid", "role": "supporting", "credentialTypes": ["pid-vct"], "claims": ["given_name"] }
                    ],
                    "credentialGroups": [
                      {
                        "id": "primary-identity",
                        "options": [["passport"], ["national-id"]]
                      },
                      {
                        "id": "pid-support",
                        "options": [["pid"]]
                      }
                    ]
                  }
                ]
                """));

        AuthenticationProfile profile = new OID4VPProfileConfig(config).getProfile("grouped");

        assertEquals(2, profile.getCredentialGroups().size());
        assertEquals(
                List.of(List.of("passport"), List.of("national-id")),
                profile.getCredentialGroups().getFirst().getOptions());
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

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(config);

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

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(config);

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

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(config);

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

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertEquals("OpenID4VP profile must have exactly one primary credential: broken", error.getMessage());
    }

    @Test
    void shouldRejectCredentialGroupWithoutConsistentPrimarySelection() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "broken",
                    "credentials": [
                      { "id": "passport", "role": "primary", "credentialTypes": ["passport-vct"], "claims": ["sub", "username"] },
                      { "id": "pid", "role": "supporting", "credentialTypes": ["pid-vct"], "claims": ["given_name"] }
                    ],
                    "credentialGroups": [
                      {
                        "id": "primary-identity",
                        "options": [["passport"], ["pid"]]
                      }
                    ]
                  }
                ]
                """));

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertEquals(
                "OpenID4VP credential group options must consistently select a primary credential: broken/primary-identity",
                error.getMessage());
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

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertEquals("OpenID4VP credential ids must be unique in profile: broken", error.getMessage());
    }

    @Test
    void shouldAcceptTransactionDataWithMdocPrimaryCredential() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put(PROFILES_CONFIG, """
                [
                  {
                    "id": "default",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "format": "mso_mdoc",
                        "credentialTypes": ["com.example.doctype"],
                        "claims": ["com.example.namespace1/sub", "com.example.namespace1/username"],
                        "subjectClaim": "com.example.namespace1/sub",
                        "usernameClaim": "com.example.namespace1/username",
                        "trust": [{ "type": "x5c", "anchors": ["%s"] }]
                      }
                    ]
                  }
                ]
                """.formatted(MdocBaseTest.getIssuerCertBase64()));
        configMap.put(TRANSACTION_DATA_CONFIG, "{\"type\":\"qrat\",\"credential_ids\":[\"primary\"]}");

        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(configMap);

        assertDoesNotThrow(() -> new VerifierConfig(config));
    }

    @Test
    void shouldRejectCredentialIdentityPrimaryWithoutSubAndUsername() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "login",
                    "credentials": [
                      { "id": "primary", "role": "primary", "credentialTypes": ["main-vct"], "claims": ["given_name"] }
                    ]
                  }
                ]
                """));

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertEquals(
                "OpenID4VP primary credential must request identity claims subjectClaim='sub' and usernameClaim='username': login/primary",
                error.getMessage());
    }

    @Test
    void shouldAcceptCredentialIdentityPrimaryWithConfiguredIdentityClaims() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "login",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "format": "mso_mdoc",
                        "credentialTypes": ["org.iso.18013.5.1.mDL"],
                        "claims": ["org.iso.18013.5.1/document_number", "org.iso.18013.5.1/given_name"],
                        "subjectClaim": "org.iso.18013.5.1/document_number",
                        "usernameClaim": "org.iso.18013.5.1/document_number",
                        "trust": [{ "type": "x5c", "anchors": ["%s"] }]
                      }
                    ]
                  }
                ]
                """.formatted(MdocBaseTest.getIssuerCertBase64())));

        assertDoesNotThrow(() -> new OID4VPProfileConfig(config));
    }

    @Test
    void shouldRejectCredentialIdentityPrimaryMissingConfiguredIdentityClaim() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "login",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "credentialTypes": ["main-vct"],
                        "claims": ["given_name"],
                        "subjectClaim": "given_name",
                        "usernameClaim": "family_name"
                      }
                    ]
                  }
                ]
                """));

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertEquals(
                "OpenID4VP primary credential must request identity claims subjectClaim='given_name' and usernameClaim='family_name': login/primary",
                error.getMessage());
    }

    @Test
    void shouldAcceptCredentialIdentityPrimaryWithBlankUsernameClaim() {
        // usernameClaim is optional — a blank value means subjectClaim alone is sufficient.
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "login",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "credentialTypes": ["main-vct"],
                        "claims": ["sub", "username"],
                        "usernameClaim": ""
                      }
                    ]
                  }
                ]
                """));

        assertDoesNotThrow(() -> new OID4VPProfileConfig(config));
    }

    @Test
    void shouldRejectMdocPrimaryCredentialWithBareSubjectClaim() {
        // Bare subjectClaim is rejected for mso_mdoc because
        // MdocCredentialVerifier.readClaim() searches all namespaces,
        // so a bare name like "document_number" could match in the wrong namespace.
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "login",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "format": "mso_mdoc",
                        "credentialTypes": ["org.iso.18013.5.1.mDL"],
                        "claims": ["org.iso.18013.5.1/document_number", "org.iso.18013.5.1/given_name"],
                        "subjectClaim": "document_number",
                        "usernameClaim": "org.iso.18013.5.1/document_number",
                        "trust": [{ "type": "x5c", "anchors": ["%s"] }]
                      }
                    ]
                  }
                ]
                """.formatted(MdocBaseTest.getIssuerCertBase64())));

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertTrue(error.getMessage().contains("mDoc primary credential subjectClaim must be namespace-qualified"));
    }

    @Test
    void shouldRejectMdocPrimaryCredentialWithBareUsernameClaim() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "login",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "format": "mso_mdoc",
                        "credentialTypes": ["org.iso.18013.5.1.mDL"],
                        "claims": ["org.iso.18013.5.1/document_number", "org.iso.18013.5.1/given_name"],
                        "subjectClaim": "org.iso.18013.5.1/document_number",
                        "usernameClaim": "document_number",
                        "trust": [{ "type": "x5c", "anchors": ["%s"] }]
                      }
                    ]
                  }
                ]
                """.formatted(MdocBaseTest.getIssuerCertBase64())));

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertTrue(error.getMessage().contains("mDoc primary credential usernameClaim must be namespace-qualified"));
    }

    @Test
    void shouldAcceptSessionIdentityPrimaryWithoutSubUsernameWhenBindingRulesPresent() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "stb-issuance",
                    "credentials": [
                      {
                        "id": "pid",
                        "role": "primary",
                        "identitySource": "session",
                        "credentialTypes": ["urn:eudi:pid:de:1"],
                        "claims": ["given_name", "family_name", "birth_date"],
                        "binding": [
                          {
                            "type": "claim_equals_user_attribute",
                            "credentialClaim": "family_name",
                            "userAttribute": "lastName"
                          }
                        ]
                      }
                    ]
                  }
                ]
                """));

        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(config);
        AuthenticationProfile profile = profileConfig.getProfile("stb-issuance");
        assertEquals(
                "urn:eudi:pid:de:1",
                profile.getPrimaryCredential().getCredentialTypes().getFirst());
        assertTrue(profile.getPrimaryCredential().isSessionIdentity());
    }

    @Test
    void shouldRejectMixedPrimaryIdentitySources() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "mixed-primary",
                    "credentials": [
                      {
                        "id": "wallet-login",
                        "role": "primary",
                        "credentialTypes": ["main-vct"],
                        "claims": ["sub", "username"]
                      },
                      {
                        "id": "issuance-proof",
                        "role": "primary",
                        "identitySource": "session",
                        "credentialTypes": ["pid-vct"],
                        "claims": ["given_name", "family_name"],
                        "binding": [
                          {
                            "type": "claim_equals_user_attribute",
                            "credentialClaim": "family_name",
                            "userAttribute": "lastName"
                          }
                        ]
                      }
                    ],
                    "credentialGroups": [
                      {
                        "id": "primary",
                        "required": true,
                        "options": [
                          ["wallet-login"],
                          ["issuance-proof"]
                        ]
                      }
                    ]
                  }
                ]
                """));

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertEquals(
                "OpenID4VP primary credentials must use the same identitySource: mixed-primary", error.getMessage());
    }

    @Test
    void shouldRejectSessionIdentityPrimaryWithoutBindingRules() {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, """
                [
                  {
                    "id": "stb-issuance",
                    "credentials": [
                      {
                        "id": "pid",
                        "role": "primary",
                        "identitySource": "session",
                        "credentialTypes": ["urn:eudi:pid:de:1"],
                        "claims": ["given_name", "family_name", "birth_date"]
                      }
                    ]
                  }
                ]
                """));

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> new OID4VPProfileConfig(config));
        assertEquals(
                "OpenID4VP session-identity primary credential must define binding rules: stb-issuance/pid",
                error.getMessage());
    }

    // ---- Binding rule validation -------------------------------------------

    private static final String DUAL_PROFILE_TEMPLATE = """
            [
              {
                "id": "p",
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
                    "claims": ["username", "family_name"],
                    "trust": [{ "type": "self" }],
                    "binding": [ {binding} ]
                  }
                ]
              }
            ]
            """;

    private static OID4VPProfileConfig parseProfileWithBinding(String bindingJson) {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(PROFILES_CONFIG, DUAL_PROFILE_TEMPLATE.replace("{binding}", bindingJson)));
        return new OID4VPProfileConfig(config);
    }

    @Test
    void shouldRejectBindingRuleWithBlankType() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseProfileWithBinding("""
                        { "type": "", "credentialClaim": "username", "primaryCredentialClaim": "username" }
                        """));
        assertTrue(e.getMessage().contains("binding rule type must not be blank"));
    }

    @Test
    void shouldRejectBindingRuleWithUnknownType() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseProfileWithBinding("""
                        { "type": "unknown_rule", "credentialClaim": "username", "primaryCredentialClaim": "username" }
                        """));
        assertTrue(e.getMessage().contains("Unsupported OpenID4VP binding rule type 'unknown_rule'"));
    }

    @Test
    void shouldRejectBindingRuleWithBlankCredentialClaim() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseProfileWithBinding("""
                        { "type": "claim_equals_primary_claim", "credentialClaim": "", "primaryCredentialClaim": "username" }
                        """));
        assertTrue(e.getMessage().contains("credentialClaim must not be blank"));
    }

    @Test
    void shouldRejectBindingRuleCredentialClaimNotInSupportingClaims() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseProfileWithBinding("""
                        { "type": "claim_equals_primary_claim", "credentialClaim": "email", "primaryCredentialClaim": "username" }
                        """));
        assertTrue(e.getMessage().contains("must be among the supporting credential's requested claims"));
    }

    @Test
    void shouldRejectBindingRuleWithBlankPrimaryCredentialClaim() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseProfileWithBinding("""
                        { "type": "claim_equals_primary_claim", "credentialClaim": "username", "primaryCredentialClaim": "" }
                        """));
        assertTrue(e.getMessage().contains("primaryCredentialClaim must not be blank"));
    }

    @Test
    void shouldRejectBindingRulePrimaryClaimNotInPrimaryClaims() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseProfileWithBinding("""
                        { "type": "claim_equals_primary_claim", "credentialClaim": "username", "primaryCredentialClaim": "family_name" }
                        """));
        assertTrue(e.getMessage().contains("must be among the primary credential's requested claims"));
    }

    @Test
    void shouldRejectBindingRuleWithBlankUserAttribute() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseProfileWithBinding("""
                        { "type": "claim_equals_user_attribute", "credentialClaim": "username", "userAttribute": "" }
                        """));
        assertTrue(e.getMessage().contains("userAttribute must not be blank"));
    }

    @Test
    void shouldAcceptValidBindingRule() {
        assertDoesNotThrow(() -> parseProfileWithBinding("""
                { "type": "claim_equals_primary_claim", "credentialClaim": "username", "primaryCredentialClaim": "username" }
                """));
    }

    @Test
    void shouldAcceptValidUserAttributeBindingRule() {
        assertDoesNotThrow(() -> parseProfileWithBinding("""
                { "type": "claim_equals_user_attribute", "credentialClaim": "family_name", "userAttribute": "family_name" }
                """));
    }

    // ---- mDoc trust policy validation ----------------------------------------

    private static final String MDOC_PROFILE_TEMPLATE = """
            [
              {
                "id": "p",
                "credentials": [
                  {
                    "id": "primary",
                    "role": "primary",
                    "format": "mso_mdoc",
                    "credentialTypes": ["com.example.doctype"],
                    "claims": ["com.example.ns/sub", "com.example.ns/username"],
                    "subjectClaim": "com.example.ns/sub",
                    "usernameClaim": "com.example.ns/username",
                    {trust}
                  }
                ]
              }
            ]
            """;

    private static void parseMdocProfileWithTrust(String trustJson) {
        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setConfig(Map.of(
                PROFILES_CONFIG,
                MDOC_PROFILE_TEMPLATE
                        .replace("{trust}", trustJson)
                        .replace("{anchor}", MdocBaseTest.getIssuerCertBase64())));
        new OID4VPProfileConfig(config);
    }

    @Test
    void shouldRejectMdocCredentialWithoutTrustPolicy() {
        IllegalStateException e =
                assertThrows(IllegalStateException.class, () -> parseMdocProfileWithTrust("\"trust\": []"));
        assertTrue(e.getMessage().contains("must configure at least one trust policy"));
    }

    @Test
    void shouldRejectSelfTrustForMdocCredential() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseMdocProfileWithTrust("""
                        "trust": [{ "type": "self" }]
                        """));
        assertTrue(e.getMessage().contains("Self-trust is not supported for mDoc credentials"));
    }

    @Test
    void shouldRejectUnsupportedTrustTypeForMdoc() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseMdocProfileWithTrust("""
                        "trust": [{ "type": "UnknownType", "anchors": ["{anchor}"] }]
                        """));
        assertTrue(e.getMessage().contains("Unsupported trust policy type 'UnknownType'"));
    }

    @Test
    void shouldRejectBlankTrustTypeForMdoc() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseMdocProfileWithTrust("""
                        "trust": [{ "type": "", "anchors": ["{anchor}"] }]
                        """));
        assertTrue(e.getMessage().contains("Trust policy type must not be blank"));
    }

    @Test
    void shouldRejectX5cTrustWithoutAnchors() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseMdocProfileWithTrust("""
                        "trust": [{ "type": "x5c", "anchors": [] }]
                        """));
        assertTrue(e.getMessage().contains("must declare at least one anchor"));
    }

    @Test
    void shouldRejectX5cTrustWithBlankAnchor() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseMdocProfileWithTrust("""
                        "trust": [{ "type": "x5c", "anchors": [""] }]
                        """));
        assertTrue(e.getMessage().contains("Invalid OpenID4VP profiles configuration"));
    }

    @Test
    void shouldRejectX5cTrustWithMalformedBase64Anchor() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseMdocProfileWithTrust("""
                        "trust": [{ "type": "x5c", "anchors": ["not-valid-base64!@#"] }]
                        """));
        assertTrue(e.getMessage().contains("Invalid OpenID4VP profiles configuration"));
    }

    @Test
    void shouldRejectX5cTrustWithInvalidDerAnchor() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> parseMdocProfileWithTrust("""
                        "trust": [{ "type": "x5c", "anchors": ["AQID"] }]
                        """));
        assertTrue(e.getMessage().contains("Invalid OpenID4VP profiles configuration"));
    }

    @Test
    void shouldAcceptValidX5cTrustForMdoc() {
        assertDoesNotThrow(() -> parseMdocProfileWithTrust("""
                "trust": [{ "type": "x5c", "anchors": ["{anchor}"] }]
                """));
    }
}
