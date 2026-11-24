# Admin UI (`keycloak.v2+oid4vp` admin theme)

A custom Keycloak admin console, built the official way by extending
[`@keycloak/keycloak-admin-ui`](https://www.npmjs.com/package/@keycloak/keycloak-admin-ui).
It keeps the complete stock console and adds an **EUDI Hub** entry under the
stock **Configure** navigation group. The entry is only shown for realms that
have the `oid4vp auth` authentication flow. The page exposes the **Access
certificate** tab. Pasting a portal access token loads the user's EUDI Hub
organizations through a Keycloak Admin API extension and fills the organization
dropdown. **Request certificate** creates a CSR for the realm's OpenID4VP
signing key, asks the EUDI Hub for an access certificate, stores it in the
OpenID4VP authenticator and shows it read-only until **Reset**.

The project follows the layout produced by
`pnpm create-keycloak-theme <name> admin`:

- `src/App.tsx` mirrors the stock admin console layout (`AdminClientProvider`,
  `AppContexts`, `Header`, `Page`, breadcrumbs) but supplies its own `PageNav`.
- `src/PageNav.tsx` is based on the stock navigation and keeps the same
  PatternFly markup, access checks and route matching. It adds **EUDI Hub** to
  the Configure group when the current realm has the `oid4vp auth` flow. The
  flow is looked up with the current admin client and the realm is passed
  explicitly, because the nav renders before the realm context updates the
  client's default realm. If the lookup fails, the entry stays hidden.
- `src/routes.tsx` keeps every stock route and inserts the EUDI Hub route
  before the catch-all.
- `src/EudiHubPage.tsx` is the page itself. Its header uses the stock
  `ViewHeader` and appends the “Learn more” link through `helpUrl`. The portal
  token is a `TextArea`; a JWT (with or without a `Bearer ` prefix) triggers the
  organization fetch. The organization field is a `FormSelect` with a refresh
  button, and failures use the stock alert toast on the right. The environment
  (sandbox or live) comes from the organization details, so it is not a form
  field. The certificate name is pre-filled with `Access Certificate` plus a
  random suffix. Requesting the certificate disables the form and shows the
  issued certificate in a read-only field; a success toast confirms the stored
  certificate. **Reset** only clears the form, it does not undo the authenticator
  configuration.
- `src/api.ts` calls the plugin's Keycloak Admin API extension at
  `/admin/realms/{realm}/eudi-hub/organizations`. The extension proxies the
  EUDI Hub server-side, so the browser never calls the EUDI Hub directly and the
  portal token is used only for that request. The EUDI Hub only allows its own
  portal origin through CORS, which is why the proxy is required.
- `src/utils/` holds the helpers copied from the stock console
  (`AuthWall`, `Banners`, `HelpLabel`, `useIsFeatureEnabled`, `joinPath`).
  `HelpLabel` renders the stock info icon and popover with PatternFly directly,
  because importing `HelpItem` from `@keycloak/keycloak-ui-shared` creates a
  second context instance in this bundle.

Other build details:

- `src/main.tsx` uses `createHashRouter` and a `Root` provider, like the stock
  console.
- `react` / `react-dom` stay external. The theme's `index.ftl` serves them
  through an import map from `${resourceCommonUrl}/vendor/react`.
- The base PatternFly stylesheet is imported because the package CSS only
  contains component rules, not the global CSS variables.
- Vite emits `.vite/manifest.json`; `AdminConsole` reads it to resolve the
  entry script, styles and imports.
- Vite writes to `dist/`. Maven copies `maven-resources/` into the JAR and maps
  `dist/` to `theme/keycloak.v2+oid4vp/admin/resources`.

The `@keycloak/keycloak-admin-ui` version must match the server version
(`keycloak.version` in `pom.xml`).

## EUDI Hub API proxy

The admin console cannot call the EUDI Hub directly: the EUDI Hub only allows
its own portal origin through CORS. The plugin registers an admin REST
extension at `/admin/realms/{realm}/eudi-hub` through
`EudiHubAdminResourceProviderFactory`. `EudiHubService` calls `GET /v1/me` to
list the organizations of the portal token's user and
`GET /v1/organizations/{id}` to load each organization's environment and
support URIs. Tokens may include the `Bearer ` prefix; it is stripped before the
upstream call. The token is never stored or logged.

Requesting a certificate calls
`POST /v1/organizations/{id}/access-certificates` with the certificate name, the
organization's first support URI, the environment and a PKCS#10 CSR for the
realm's OpenID4VP signing key. `EudiHubCsr` signs the CSR with that key, so the
private key never leaves Keycloak. The issued certificate is downloaded from
`GET /v1/organizations/{id}/access-certificates/{certificateId}/download` (DER),
base64-encoded and written to the `accessCertificate` field of the existing
OpenID4VP authenticator configuration. A realm whose authenticator has no
configuration is reported as a conflict instead of being changed. Requesting a
certificate needs `manage-realm`; listing organizations needs `view-realm`.

The upstream URL defaults to `https://api.eudi-hub.gov.de/org-management`. It
must use HTTPS. Override it for another deployment with:

```bash
bin/kc.sh start \
  --spi-admin-realm-restapi-extension-eudi-hub-api-url=https://example.test/org-management
```

The extension requires `view-realm` on the target realm, so it is only available
to realm administrators.

## Development

```bash
cd apps/admin-ui
pnpm install
pnpm dev        # Vite dev server with HMR
```

The theme's `index.ftl` picks up `devServerUrl` when Keycloak runs in dev mode.
The admin theme markup lives in
`apps/admin-ui/maven-resources/theme/keycloak.v2+oid4vp/admin/`. The
plugin-wide theme manifest remains in
`src/main/resources/META-INF/keycloak-themes.json`.

## Build

`mvn package` installs Node and pnpm through `frontend-maven-plugin`, runs
`pnpm install --frozen-lockfile` and `pnpm build`, then packages the bundle in
the plugin JAR under `theme/keycloak.v2+oid4vp/admin/`. Java-only builds can
skip the frontend with `-Dskip.pnpm`; in that case an existing
`apps/admin-ui/dist/` is packaged.

## Enable it

Select `keycloak.v2+oid4vp` as the realm's admin theme (Realm Settings →
Themes), or:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$KEYCLOAK/admin/realms/$REALM" -d '{"adminTheme":"keycloak.v2+oid4vp"}'
```

Then open `/$KEYCLOAK/admin/$REALM/console/`. **EUDI Hub** appears under
**Configure** when the realm has the `oid4vp auth` authentication flow. The
console authenticates against that realm's own `security-admin-console` client,
so the user needs admin rights in that realm.
