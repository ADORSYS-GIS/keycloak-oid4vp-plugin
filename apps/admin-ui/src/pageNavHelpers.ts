import { useAdminClient, useRealm } from "@keycloak/keycloak-admin-ui";
import type { TFunction } from "i18next";
import { useEffect, useState } from "react";
import { generatePath } from "react-router-dom";

// The EUDI Hub entry is only meaningful for realms that have the flow the
// plugin installs.
const OID4VP_AUTH_FLOW = "oid4vp auth";

// Same display-name handling as the stock console: a `${...}` value is a
// message bundle key.
export const resolveDisplayName = (t: TFunction, displayName?: string, fallback = "") => {
  if (displayName?.startsWith("${") && displayName.endsWith("}")) {
    return t(displayName.substring(2, displayName.length - 1));
  }
  return displayName || fallback;
};

// Same normalization the stock console uses to match a nav path against the
// route definitions (`/clients/:id` -> `/clients`).
export const normalizeNavRoutePath = (routePath: string): string =>
  routePath.replace(/\/:.+?(\?|(?:(?!\/).)*|$)/g, "").replace(/\/\*$/, "");

// Mirrors `toPage` from the stock console for declarative UI pages.
export const toPage = (providerId: string) =>
  generatePath("/:realm?/page-section/:providerId", { providerId });

export const useHasOid4vpAuthFlow = () => {
  const { adminClient } = useAdminClient();
  const { realm } = useRealm();
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setEnabled(false);

    adminClient.authenticationManagement
      .getFlows({ realm })
      .then((flows) => {
        if (!cancelled) {
          setEnabled(flows.some((flow) => flow.alias === OID4VP_AUTH_FLOW));
        }
      })
      .catch(() => {
        // A missing permission or a transient failure keeps the entry hidden
        // instead of breaking the console.
        if (!cancelled) {
          setEnabled(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [adminClient, realm]);

  return enabled;
};
