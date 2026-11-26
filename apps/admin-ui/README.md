# Admin UI

This admin theme extends Keycloak's stock console with an **EUDI Hub** page under **Configure**. The
page requests an access certificate and stores it on the OpenID4VP authenticator, creating its
configuration if needed.

## Use the EUDI Hub page

1. Set the admin theme to `keycloak.v2+oid4vp` on the realm the admin user signs into, usually
   `master`. This can differ from the realm you need to configure.
2. Switch to the OpenID4VP realm and select **Configure** > **EUDI Hub**.
3. Follow the on-screen instructions to obtain a portal access token, then request the certificate.
   The page configures it automatically.

To include this access certificate in signed Credential Issuer Metadata, set the target realm
attribute `oid4vci.patch_metadata_x5c_to_oid4vp_access_certificate` to `true`.

## Development

```bash
cd apps/admin-ui
pnpm install --frozen-lockfile
pnpm check
pnpm dev
```

Maven builds package the UI into the plugin JAR. The `@keycloak/keycloak-admin-ui` dependency must
match `keycloak.version` in the root `pom.xml`.
