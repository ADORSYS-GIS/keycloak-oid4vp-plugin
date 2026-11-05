export const REALM_NAME = "oid4vc-vci";

// Status List Server used by the token-status plugin for revocation.
export const STATUS_LIST_SERVER_URL =
  process.env.STATUS_LIST_SERVER_URL ?? "https://statuslist.eudi-adorsys.com";

// Issuer identity prefix on the status list server (`<prefix>::<realm>`).
// Pinned so a new "issuer" is not registered on every run.
export const STATUS_LIST_TOKEN_ISSUER_PREFIX = "7bbf03bc-e2f5-4754-a761-f1b6125db40d";

// Issuer identity of the issued Identity VC (must equal the `vct` checked by
// the OpenID4VP authenticator below).
export const IDENTITY_CREDENTIAL_VCT = "https://credentials.example.com/identity_credential";

// Ports the browser and the tests rely on (must match docker-compose.yml).
export const KEYCLOAK_HTTP_PORT = Number(process.env.KEYCLOAK_HTTP_PORT ?? 18080);
export const MOCK_FE_HTTP_PORT = Number(process.env.MOCK_FE_HTTP_PORT ?? 14200);
