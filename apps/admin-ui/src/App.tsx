import {
  AdminClientProvider,
  AppContexts,
  Header,
  PageBreadCrumbs,
} from "@keycloak/keycloak-admin-ui";
import { KeycloakSpinner, mainPageContentId } from "@keycloak/keycloak-ui-shared";
import { Flex, FlexItem, Page } from "@patternfly/react-core";
import { Suspense, useEffect } from "react";
import { Outlet } from "react-router-dom";
import { PageNav } from "./PageNav";
import { AuthWall } from "./utils/AuthWall";
import { Banners } from "./utils/Banners";

// Mirrors the stock admin console layout, but uses our navigation so the
// EUDI Hub page can be added as a regular nav item next to the stock pages.
export const App = () => {
  const hrefEndsWithHashSlash = location.href.endsWith("#/");

  useEffect(() => {
    if (!hrefEndsWithHashSlash) return;
    history.replaceState(null, "", location.pathname);
  }, [hrefEndsWithHashSlash, location.pathname]);

  return (
    <AdminClientProvider>
      <AppContexts>
        <Flex
          direction={{ default: "column" }}
          flexWrap={{ default: "nowrap" }}
          spaceItems={{ default: "spaceItemsNone" }}
          style={{ height: "100%" }}
        >
          <FlexItem>
            <Banners />
          </FlexItem>
          <FlexItem grow={{ default: "grow" }} style={{ minHeight: 0 }}>
            <Page
              header={<Header />}
              isManagedSidebar
              sidebar={<PageNav />}
              breadcrumb={<PageBreadCrumbs />}
              mainContainerId={mainPageContentId}
            >
              <Suspense fallback={<KeycloakSpinner />}>
                <AuthWall>
                  <Outlet />
                </AuthWall>
              </Suspense>
            </Page>
          </FlexItem>
        </Flex>
      </AppContexts>
    </AdminClientProvider>
  );
};
