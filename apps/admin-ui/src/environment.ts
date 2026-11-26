import type { AdminEnvironment } from "@keycloak/keycloak-admin-ui";
import { getInjectedEnvironment } from "@keycloak/keycloak-ui-shared";

export const environment = getInjectedEnvironment<AdminEnvironment>();
