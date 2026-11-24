import {
  useAccess,
  useAdminClient,
  useEnvironment,
  useRealm,
  useServerInfo,
  type AdminEnvironment,
} from "@keycloak/keycloak-admin-ui";
import {
  Label,
  Nav,
  NavGroup,
  PageSidebar,
  PageSidebarBody,
} from "@patternfly/react-core";
import { FormEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { NavLink, generatePath, useNavigate } from "react-router-dom";
import { routes } from "./routes";
import useIsFeatureEnabled, { Feature } from "./utils/useIsFeatureEnabled";

// The EUDI Hub entry is only meaningful for realms that have the flow the
// plugin installs.
const OID4VP_AUTH_FLOW = "oid4vp auth";

// Same display-name handling as the stock console: a `${...}` value is a
// message bundle key.
const resolveDisplayName = (
  t: TFunction,
  displayName?: string,
  fallback = "",
) => {
  if (displayName && displayName.includes("${")) {
    return t(displayName.substring(2, displayName.length - 1));
  }
  return displayName || fallback;
};

// Same normalization the stock console uses to match a nav path against the
// route definitions (`/clients/:id` -> `/clients`).
const normalizeNavRoutePath = (routePath: string): string =>
  routePath.replace(/\/:.+?(\?|(?:(?!\/).)*|$)/g, "").replace(/\/\*$/, "");

// Mirrors `toPage` from the stock console for declarative UI pages.
const toPage = (providerId: string) =>
  generatePath("/:realm?/page-section/:providerId", { providerId });

const useHasOid4vpAuthFlow = () => {
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

type LeftNavProps = {
  title: string;
  path: string;
  id?: string;
};

const LeftNav = ({ title, path, id }: LeftNavProps) => {
  const { t } = useTranslation();
  const { hasAccess } = useAccess();
  const { realm } = useRealm();
  const encodedRealm = encodeURIComponent(realm);
  const navPath = id || path;
  const route = routes.find(
    (route) => normalizeNavRoutePath(route.path) === navPath,
  );

  const accessAllowed =
    route &&
    (route.handle.access instanceof Array
      ? hasAccess(...route.handle.access)
      : hasAccess(route.handle.access));

  if (!accessAllowed) {
    return undefined;
  }

  // Keep the stock id for regular links while staying unique for declarative
  // pages, where several entries share the `/page-section` route prefix.
  const name =
    "nav-item" + (id ? `${id}/${path}` : path).replace(/\//g, "-");
  return (
    <li>
      <NavLink
        id={name}
        data-testid={name}
        to={`/${encodedRealm}${path}`}
        className={({ isActive }) =>
          `pf-v5-c-nav__link${isActive ? " pf-m-current" : ""}`
        }
      >
        {t(title)}
      </NavLink>
    </li>
  );
};

export const PageNav = () => {
  const { t } = useTranslation();
  const { environment } = useEnvironment<AdminEnvironment>();
  const { hasSomeAccess } = useAccess();
  const { componentTypes } = useServerInfo();
  const isFeatureEnabled = useIsFeatureEnabled();
  const hasOid4vpAuthFlow = useHasOid4vpAuthFlow();
  const pages =
    componentTypes?.["org.keycloak.services.ui.extend.UiPageProvider"];
  const navigate = useNavigate();
  const { realm, realmRepresentation } = useRealm();

  type SelectedItem = {
    groupId: number | string;
    itemId: number | string;
    to: string;
    event: FormEvent<HTMLInputElement>;
  };

  const onSelect = (item: SelectedItem) => {
    void navigate(item.to);
    item.event.preventDefault();
  };

  const showManage = hasSomeAccess(
    "view-realm",
    "query-groups",
    "query-users",
    "query-clients",
    "query-organizations",
    "view-events",
  );

  const showConfigure = hasSomeAccess(
    "view-realm",
    "query-clients",
    "view-identity-providers",
  );

  const showWorkflows =
    hasSomeAccess("realm-admin", "admin") &&
    isFeatureEnabled(Feature.Workflows);

  const showManageRealm = environment.masterRealm === environment.realm;

  return (
    <PageSidebar className="keycloak__page_nav__nav">
      <PageSidebarBody>
        <Nav onSelect={(_event, item) => onSelect(item as SelectedItem)}>
          <h2
            className="pf-v5-c-nav__section-title"
            style={{ wordWrap: "break-word" }}
          >
            <span data-testid="currentRealm">
              {resolveDisplayName(
                t,
                realmRepresentation.displayName,
                realm,
              )}
            </span>{" "}
            <Label color="blue">{t("currentRealm")}</Label>
          </h2>
          {showManageRealm && (
            <NavGroup>
              <LeftNav title={t("manageRealms")} path="/realms" />
            </NavGroup>
          )}
          {showManage && (
            <NavGroup aria-label={t("manage")} title={t("manage")}>
              {isFeatureEnabled(Feature.Organizations) &&
                realmRepresentation.organizationsEnabled && (
                  <LeftNav title="organizations" path="/organizations" />
                )}
              <LeftNav title="clients" path="/clients" />
              <LeftNav title="clientScopes" path="/client-scopes" />
              <LeftNav title="realmRoles" path="/roles" />
              <LeftNav title="users" path="/users" />
              <LeftNav title="groups" path="/groups" />
              <LeftNav title="sessions" path="/sessions" />
              <LeftNav title="events" path="/events" />
            </NavGroup>
          )}

          {showConfigure && (
            <NavGroup aria-label={t("configure")} title={t("configure")}>
              <LeftNav title="realmSettings" path="/realm-settings" />
              <LeftNav title="authentication" path="/authentication" />
              {isFeatureEnabled(Feature.AdminFineGrainedAuthzV2) &&
                realmRepresentation.adminPermissionsEnabled && (
                  <LeftNav title="permissions" path="/permissions" />
                )}
              <LeftNav title="identityProviders" path="/identity-providers" />
              <LeftNav title="userFederation" path="/user-federation" />
              {showWorkflows && <LeftNav title="workflows" path="/workflows" />}
              {isFeatureEnabled(Feature.DeclarativeUI) &&
                pages?.map((p) => (
                  <LeftNav
                    key={p.id}
                    title={p.id}
                    path={toPage(p.id)}
                    id="/page-section"
                  />
                ))}
              {hasOid4vpAuthFlow && (
                <LeftNav title="eudiHub" path="/eudi-hub" />
              )}
            </NavGroup>
          )}
        </Nav>
      </PageSidebarBody>
    </PageSidebar>
  );
};
