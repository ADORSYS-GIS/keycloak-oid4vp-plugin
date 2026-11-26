import "@patternfly/patternfly/patternfly-addons.css";
import "@patternfly/react-core/dist/styles/base.css";
import "@keycloak/keycloak-admin-ui/styles.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createHashRouter, RouterProvider } from "react-router-dom";
import { I18nextProvider } from "react-i18next";
import { i18n } from "./i18n";
import { Root } from "./copy/Root";
import { routes } from "./routes";

import "./copy/index.css";

// Initialize required components before rendering app.
await i18n.init();

const router = createHashRouter([
  {
    path: "/",
    element: (
      <I18nextProvider i18n={i18n}>
        <Root />
      </I18nextProvider>
    ),
    children: routes,
  },
]);
const container = document.getElementById("app");
const root = createRoot(container!);

root.render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
