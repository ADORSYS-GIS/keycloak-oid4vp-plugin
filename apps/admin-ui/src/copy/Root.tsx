import { KeycloakProvider } from "@keycloak/keycloak-admin-ui";

import { App } from "./App";
import { environment } from "../environment";

export const Root = () => (
  <KeycloakProvider environment={environment}>
    <App />
  </KeycloakProvider>
);
