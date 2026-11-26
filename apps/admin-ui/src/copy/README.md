# Upstream Keycloak copies

These files are based on Keycloak **26.8.2**:

- `App.tsx`, `index.css`, `Banners.tsx`, `banners.module.css`, `Root.tsx` — `js/apps/admin-ui/src/`
- `AuthWall.tsx` — `js/apps/admin-ui/src/root/`
- `joinPath.ts`, `useIsFeatureEnabled.ts` — `js/apps/admin-ui/src/utils/`

Imports are adapted to use the published Keycloak UI packages rather than
Keycloak's monorepo-internal modules. The plugin-specific entrypoint remains at
`src/main.tsx` with its custom routes, i18n, and stylesheet setup.
