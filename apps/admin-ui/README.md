# Admin UI (`keycloak.v2+oid4vp` admin theme)

A custom Keycloak admin console, built the official way by extending
[`@keycloak/keycloak-admin-ui`](https://www.npmjs.com/package/@keycloak/keycloak-admin-ui).
It keeps the complete stock console and adds an **EUDI Hub** entry under the
stock **Configure** navigation group. The entry is only shown for realms that
have the `oid4vp auth` authentication flow. The page currently exposes the
**Access certificates** tab and the form fields the EUDI Hub request needs; the
backend request is not wired yet.

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
  `ViewHeader` and appends the “Learn more” link through `helpUrl`.
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
