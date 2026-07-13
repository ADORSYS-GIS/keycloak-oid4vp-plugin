package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointTest.VCT_CONFIG_ALT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;

/**
 * Sample authentication profile configurations for end-to-end OpenID4VP tests.
 *
 * <p>Profile JSON templates use {@code {named}} placeholders (filled via {@link String#replace})
 * so that the structure and intent of each sample remain easy to read at a glance.
 */
public final class AuthenticationProfileSamples {

    public static final String DUAL_PROFILE_ID = "dual";
    public static final String MDOC_PRIMARY_PROFILE_ID = "mdoc-primary";
    public static final String SDJWT_MDOC_DUAL_PROFILE_ID = "sdjwt-mdoc-dual";

    /** Credential id used for the primary credential in multi-credential profiles and VP token maps. */
    public static final String PRIMARY_CREDENTIAL_ID = "primary";

    /** Credential id used for the supporting credential in dual-credential profiles and VP token maps. */
    public static final String SUPPORTING_CREDENTIAL_ID = "supporting";

    /**
     * Bundles a profile's JSON configuration with its identifier, so callers of
     * {@code withAuthenticationProfile} need only pass the sample object rather than repeating
     * the matching {@code *_PROFILE_ID} constant.
     */
    public record ProfileSample(String json, String profileId) {}

    private AuthenticationProfileSamples() {}

    /** Dual SD-JWT profile: primary + self-trusted supporting, bound on username. */
    public static ProfileSample dualProfile() {
        String json = """
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
        return new ProfileSample(json, DUAL_PROFILE_ID);
    }

    /** Single primary mso_mdoc credential secured by an x5c trust anchor. */
    public static ProfileSample mdocPrimary() {
        return mdocPrimaryWithAnchor(MdocBaseTest.getIssuerCertBase64());
    }

    /**
     * Like {@link #mdocPrimary()} but secures the primary mDoc credential with the given x5c
     * trust anchor (Base64) instead of the default issuer certificate.
     */
    public static ProfileSample mdocPrimaryWithAnchor(String anchorBase64) {
        String json = """
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
                          { "type": "x5c", "anchors": ["{anchorBase64}"] }
                        ]
                      }
                    ]
                  }
                ]
                """.replace("{mdocPrimaryProfileId}", MDOC_PRIMARY_PROFILE_ID)
                .replace("{docType}", MdocBaseTest.DOC_TYPE)
                .replace("{namespace}", MdocBaseTest.NAMESPACE)
                .replace("{anchorBase64}", anchorBase64);
        return new ProfileSample(json, MDOC_PRIMARY_PROFILE_ID);
    }

    /** SD-JWT primary + mso_mdoc supporting, x5c-trusted, bound on username. */
    public static ProfileSample sdjwtMdocDual() {
        String json = """
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
        return new ProfileSample(json, SDJWT_MDOC_DUAL_PROFILE_ID);
    }
}
