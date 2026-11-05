export const REALM_NAME = "oid4vc-vci";

// Status List Server used by the token-status plugin for revocation. The e2e
// stack runs its own instance (see docker-compose.yml) behind a TLS proxy
// reachable from inside the compose network at https://status-list:8443.
export const STATUS_LIST_SERVER_URL =
  process.env.STATUS_LIST_SERVER_URL ?? "https://status-list:8443";

// Filesystem path (inside the Keycloak container) of the CA that signs the
// local status-list-server's certificate. The token-status publishing plugin's
// HTTPS client trusts this CA for TLS (see docker-compose.yml mount).
export const STATUS_LIST_TLS_CA_CERT_PATH =
  process.env.STATUS_LIST_TLS_CA_CERT_PATH ?? "/opt/keycloak/data/status-list/ca.crt";

// Issuer identity prefix on the status list server (`<prefix>::<realm>`).
// Pinned so a new "issuer" is not registered on every run.
export const STATUS_LIST_TOKEN_ISSUER_PREFIX = "7bbf03bc-e2f5-4754-a761-f1b6125db40d";

// Issuer identity of the issued Identity VC (must equal the `vct` checked by
// the OpenID4VP authenticator below).
export const IDENTITY_CREDENTIAL_VCT = "https://credentials.example.com/identity_credential";

// Ports the browser and the tests rely on (must match docker-compose.yml).
export const KEYCLOAK_HTTP_PORT = Number(process.env.KEYCLOAK_HTTP_PORT ?? 18080);
export const MOCK_FE_HTTP_PORT = Number(process.env.MOCK_FE_HTTP_PORT ?? 14200);
