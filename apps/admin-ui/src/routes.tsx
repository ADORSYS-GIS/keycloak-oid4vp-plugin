import type { AccessType } from "@keycloak/keycloak-admin-client/lib/defs/whoAmIRepresentation";
import { routes as stockRoutes } from "@keycloak/keycloak-admin-ui";
import type { NonIndexRouteObject } from "react-router-dom";
import { EudiHubPage } from "./EudiHubPage";

type AppRoute = NonIndexRouteObject & {
  path: string;
  handle: {
    access: AccessType | AccessType[];
    breadcrumb?: unknown;
  };
};

const EudiHubRoute: AppRoute = {
  path: "/:realm/eudi-hub",
  element: <EudiHubPage />,
  handle: {
    access: "view-realm",
  },
};

// Keep every stock route and insert only the EUDI Hub page. The catch-all
// stays last.
const notFound = stockRoutes.filter((route) => route.path === "*");
const rest = stockRoutes.filter((route) => route.path !== "*");

export const routes: AppRoute[] = [
  EudiHubRoute,
  ...(rest as AppRoute[]),
  ...(notFound as AppRoute[]),
];
