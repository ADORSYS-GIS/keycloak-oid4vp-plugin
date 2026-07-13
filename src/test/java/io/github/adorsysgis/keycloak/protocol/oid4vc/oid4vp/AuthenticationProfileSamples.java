package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;

/**
 * Sample authentication profile configurations for end-to-end OpenID4VP tests.
 *
 * <p>Profile JSON templates use {@code {named}} placeholders (filled via {@link String#replace})
 * so that the structure and intent of each sample remain easy to read at a glance.
 */
public final class AuthenticationProfileSamples {

    /** Alternative VCT accepted by the test authenticator alongside the default. */
    public static final String VCT_CONFIG_ALT = "https://example.com/vct-alt";

    public static final String DUAL_PROFILE_ID = "dual";
    public static final String MDOC_PRIMARY_PROFILE_ID = "mdoc-primary";
    public static final String SDJWT_MDOC_DUAL_PROFILE_ID = "sdjwt-mdoc-dual";

    private AuthenticationProfileSamples() {}

    /** Dual SD-JWT profile: primary + self-trusted supporting, bound on username. */
    public static String dualProfile() {
        return """
                [
                  {
                    "id": "default",
                    "displayCta": { "en": "Sign in with a wallet" },
                    "credentials": [
                      {
                        "id": "identity",
                        "role": "primary",
                        "credentialTypes": ["{defaultVct}", "{altVct}"],
                        "claims": ["sub", "username"]
                      }
                    ]
                  },
                  {
                    "id": "{dualProfileId}",
                    "displayCta": { "en": "Sign in with two credentials" },
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "credentialTypes": ["{defaultVct}"],
                        "claims": ["sub", "username"]
                      },
                      {
                        "id": "supporting",
                        "role": "supporting",
                        "credentialTypes": ["{defaultVct}"],
                        "claims": ["username"],
                        "trust": [{ "type": "self" }],
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
                """.replace("{defaultVct}", CREDENTIAL_TYPES_CONFIG_DEFAULT)
                .replace("{altVct}", VCT_CONFIG_ALT)
                .replace("{dualProfileId}", DUAL_PROFILE_ID);
    }

    /** Single primary mso_mdoc credential secured by an x5c trust anchor. */
    public static String mdocPrimary() {
        return """
                [
                  {
                    "id": "{mdocPrimaryProfileId}",
                    "displayCta": { "en": "Sign in with an mDoc wallet" },
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "format": "mso_mdoc",
                        "credentialTypes": ["{docType}"],
                        "claims": ["{namespace}/sub", "{namespace}/username"],
                        "trust": [
                          { "type": "x5c", "anchors": ["{issuerCertBase64}"] }
                        ]
                      }
                    ]
                  }
                ]
                """.replace("{mdocPrimaryProfileId}", MDOC_PRIMARY_PROFILE_ID)
                .replace("{docType}", MdocBaseTest.DOC_TYPE)
                .replace("{namespace}", MdocBaseTest.NAMESPACE)
                .replace("{issuerCertBase64}", MdocBaseTest.getIssuerCertBase64());
    }

    /** SD-JWT primary + mso_mdoc supporting, x5c-trusted, bound on username. */
    public static String sdjwtMdocDual() {
        return """
                [
                  {
                    "id": "default",
                    "displayCta": { "en": "Sign in with a wallet" },
                    "credentials": [
                      {
                        "id": "identity",
                        "role": "primary",
                        "credentialTypes": ["{defaultVct}", "{altVct}"],
                        "claims": ["sub", "username"]
                      }
                    ]
                  },
                  {
                    "id": "{sdjwtMdocDualProfileId}",
                    "displayCta": { "en": "Sign in with SD-JWT and mDoc" },
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "credentialTypes": ["{defaultVct}"],
                        "claims": ["sub", "username"]
                      },
                      {
                        "id": "supporting",
                        "role": "supporting",
                        "format": "mso_mdoc",
                        "credentialTypes": ["{docType}"],
                        "claims": ["{namespace}/username"],
                        "trust": [
                          { "type": "x5c", "anchors": ["{issuerCertBase64}"] }
                        ],
                        "binding": [
                          {
                            "type": "claim_equals_primary_claim",
                            "credentialClaim": "{namespace}/username",
                            "primaryCredentialClaim": "username"
                          }
                        ]
                      }
                    ]
                  }
                ]
                """.replace("{defaultVct}", CREDENTIAL_TYPES_CONFIG_DEFAULT)
                .replace("{altVct}", VCT_CONFIG_ALT)
                .replace("{sdjwtMdocDualProfileId}", SDJWT_MDOC_DUAL_PROFILE_ID)
                .replace("{docType}", MdocBaseTest.DOC_TYPE)
                .replace("{namespace}", MdocBaseTest.NAMESPACE)
                .replace("{issuerCertBase64}", MdocBaseTest.getIssuerCertBase64());
    }
}
