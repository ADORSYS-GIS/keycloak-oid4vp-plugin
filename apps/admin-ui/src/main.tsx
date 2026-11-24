import "@patternfly/patternfly/patternfly-addons.css";
import "@patternfly/react-core/dist/styles/base.css";
import "@keycloak/keycloak-admin-ui/styles.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createHashRouter, RouterProvider } from "react-router-dom";

import { i18n } from "./i18n";
import { Root } from "./Root";
import { routes } from "./routes";
import "./index.css";

// A failed message-bundle fetch must not stop the console from rendering.
await i18n.init().catch((error) => {
  console.error("i18n initialization failed", error);
});

const router = createHashRouter([
  {
    path: "/",
    element: <Root />,
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
