import { routes as stockRoutes } from "@keycloak/keycloak-admin-ui";
import { EudiHubPage } from "./EudiHubPage";

const EudiHubRoute: (typeof stockRoutes)[number] = {
  path: "/:realm/eudi-hub",
  element: <EudiHubPage />,
  handle: {
    access: "view-realm",
  },
};

export const routes = [EudiHubRoute, ...stockRoutes];
