// The realm of the credential journey, written as code and rendered
// by scripts/setup.sh.

import {
  IDENTITY_CREDENTIAL_VCT,
  KEYCLOAK_HTTP_PORT,
  MOCK_FE_HTTP_PORT,
  REALM_NAME,
  STATUS_LIST_SERVER_URL,
  STATUS_LIST_TOKEN_ISSUER_PREFIX,
} from "./config.ts";
import { mapper } from "./mappers.ts";

// ---- The realm ---------------------------------------------------------------

const realm = {
  id: REALM_NAME,
  realm: REALM_NAME,
  enabled: true,
  sslRequired: "none",
  loginTheme: "keycloak.v2+oid4vp",
  verifiableCredentialsEnabled: true,

  attributes: {
    preAuthorizedCodeLifespanS: "120",
    "status-list-enabled": "true",
    "status-list-server-url": STATUS_LIST_SERVER_URL,
    "status-list-token-issuer-prefix": STATUS_LIST_TOKEN_ISSUER_PREFIX,
  },

  users: [
    {
      id: "alice@localhost-id",
      username: "alice@localhost",
      enabled: true,
      email: "alice@localhost",
      firstName: "Alice",
      lastName: "Smith",
      credentials: [{ type: "password", value: "password" }],
      realmRoles: ["credential-offer-create"],
    },
    {
      id: "bob@localhost-id",
      username: "bob@localhost",
      enabled: true,
      email: "bob@localhost",
      firstName: "Bob",
      lastName: "Smith",
      credentials: [{ type: "password", value: "password" }],
    },
  ],

  // The IdentityCredential: issued as dc+sd-jwt with key binding, exposing
  // the revocation status claim of the token-status plugin.
  clientScopes: [
    {
      name: "IdentityCredential",
      protocol: "oid4vc",
      attributes: {
        "include.in.token.scope": "true",
        "vc.credential_configuration_id": "IdentityCredential",
        "vc.credential_identifier": "IdentityCredential",
        "vc.format": "dc+sd-jwt",
        "vc.expiry_in_seconds": 31536000,
        "vc.verifiable_credential_type": IDENTITY_CREDENTIAL_VCT,
        "vc.supported_credential_types": "identity_credential",
        "vc.credential_contexts": IDENTITY_CREDENTIAL_VCT,
        "vc.cryptographic_binding_methods_supported": "jwk",
        "vc.credential_signing_alg": "ES256",
        "vc.display": '[{"name": "Identity Credential"}]',
        "vc.sd_jwt.number_of_decoys": "2",
        // `status` is what the token-status plugin appends for revocation.
        "vc.credential_build_config.sd_jwt.visible_claims": "sub,iat,nbf,exp,jti,status",
        "vc.credential_build_config.hash_algorithm": "sha-256",
        "vc.credential_build_config.token_jws_type": "dc+sd-jwt",
        "vc.include_in_metadata": "true",
        "vc.binding_required": "true",
        "vc.binding_methods_supported": "jwk",
        "vc.binding_required_proof_types": "jwt",
      },
      protocolMappers: [
        mapper.givenName(),
        mapper.familyName(),
        mapper.issuedAt(),
        mapper.notBefore(),
        mapper.subject(),
        mapper.statusListClaim(),
      ],
    },
  ],

  clients: [
    {
      clientId: "oid4vc-demo-public",
      name: "Oid4vc Demo frontend",
      enabled: true,
      publicClient: true,
      // Direct grants only exist so maintainers can probe endpoints with
      // curl during debugging; the journey itself never uses them.
      directAccessGrantsEnabled: true,
      redirectUris: [
        `http://keycloak.localhost:${KEYCLOAK_HTTP_PORT}/*`,
        `http://localhost:${MOCK_FE_HTTP_PORT}/*`,
      ],
      webOrigins: [
        `http://keycloak.localhost:${KEYCLOAK_HTTP_PORT}`,
        `http://localhost:${MOCK_FE_HTTP_PORT}`,
      ],
      frontchannelLogout: true,
      protocol: "openid-connect",
      attributes: {
        "oid4vci.enabled": "true",
        "post.logout.redirect.uris": "+",
      },
      defaultClientScopes: ["web-origins", "acr", "roles", "profile", "basic", "email"],
      optionalClientScopes: ["IdentityCredential"],
    },
    {
      clientId: "test-app",
      name: "Test app",
      enabled: true,
      publicClient: true,
      redirectUris: ["http://localhost:*", `http://localhost:${KEYCLOAK_HTTP_PORT}/*`],
      protocol: "openid-connect",
      attributes: {
        "oid4vci.enabled": "true",
      },
    },
  ],

  authenticationFlows: [
    {
      // Exactly the alias the plugin's endpoints resolve (hardcoded upstream).
      alias: "oid4vp auth",
      description: "Authenticate via OpenID4VP presentations of identity credentials",
      providerId: "basic-flow",
      topLevel: true,
      builtIn: false,
      authenticationExecutions: [
        {
          authenticator: "oid4vp-authenticator",
          authenticatorConfig: "oid4vp-auth-config",
          authenticatorFlow: false,
          requirement: "REQUIRED",
          priority: 0,
          userSetupAllowed: false,
        },
      ],
    },
  ],

  authenticatorConfig: [
    {
      alias: "oid4vp-auth-config",
      config: {
        // The credential type the wallet must present to log in.
        vct: IDENTITY_CREDENTIAL_VCT,
        // This is the whole point of the journey: once the token-status
        // plugin revokes the credential, the presentation is rejected.
        enforceRevocationStatus: "true",
      },
    },
  ],

  // One keystore, both signing purposes (mounted by docker-compose.yml):
  // - ES256 signs the issued credentials (HAIP requires a CA-signed leaf).
  // - RS256 is what the realm's default signature algorithm points at, and
  //   the token-status plugin signs its registry JWT with the realm's
  //   default (RS256) key — so both entries live in the committed store.
  components: {
    "org.keycloak.keys.KeyProvider": [
      {
        name: "custom-ecdsa",
        providerId: "java-keystore",
        config: {
          algorithm: ["ES256"],
          active: ["true"],
          enabled: ["true"],
          priority: ["300"],
          kid: ["oid4vci-ec-issuer"],
          keystore: [`/opt/keycloak/data/${REALM_NAME}/keystore.p12`],
          keystorePassword: ["password"],
          keystoreType: ["PKCS12"],
          keyAlias: ["oid4vci-ec-issuer"],
          keyPassword: ["password"],
        },
      },
      {
        name: "custom-rsa",
        providerId: "java-keystore",
        config: {
          algorithm: ["RS256"],
          active: ["true"],
          enabled: ["true"],
          priority: ["100"],
          kid: ["4EmuYdD6ap3Y9hlJ6T18coOPVPERdKNkGRluUZ30IHA"],
          keystore: [`/opt/keycloak/data/${REALM_NAME}/keystore.p12`],
          keystorePassword: ["password"],
          keystoreType: ["PKCS12"],
          keyAlias: ["oid4vci-issuer"],
          keyPassword: ["password"],
        },
      },
    ],
  },
};

// ---- Render --------------------------------------------------------------------

process.stdout.write(JSON.stringify(realm, null, 2) + "\n");
