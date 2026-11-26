import type { AccessType } from "@keycloak/keycloak-admin-client/lib/defs/whoAmIRepresentation";
import { ForbiddenSection, useAccess } from "@keycloak/keycloak-admin-ui";
import type { ReactNode } from "react";
import { useMatches } from "react-router-dom";

function hasProp<K extends PropertyKey>(
  data: object,
  prop: K,
): data is Record<K, unknown> {
  return prop in data;
}

type AuthWallProps = {
  children: ReactNode;
};

export const AuthWall = ({ children }: AuthWallProps) => {
  const matches = useMatches();
  const { hasAccess } = useAccess();

  const permissionNeeded = matches.flatMap(({ handle }) => {
    if (
      typeof handle !== "object" ||
      handle === null ||
      !hasProp(handle, "access")
    ) {
      return [];
    }

    if (Array.isArray(handle.access)) {
      return handle.access as AccessType[];
    }

    return [handle.access] as AccessType[];
  });

  if (!hasAccess(...permissionNeeded)) {
    return <ForbiddenSection permissionNeeded={permissionNeeded} />;
  }

  return children;
};
