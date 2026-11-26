import { createInstance } from "i18next";
import FetchBackend from "i18next-fetch-backend";
import { initReactI18next } from "react-i18next";
import type { i18n as i18nType } from "i18next";
import { environment } from "./environment";
import { joinPath } from "./copy/joinPath";

type KeyValue = { key: string; value: string };

// Keep plugin messages tied to the master admin theme. `environment.realm`
// can be the realm currently being managed, whose admin theme may not contain
// this plugin's message bundle.
const ns = environment.masterRealm;

export const i18n: i18nType = createInstance({
  fallbackLng: "en",
  keySeparator: ".",
  nsSeparator: false,
  interpolation: {
    escapeValue: false,
  },
  defaultNS: [ns],
  ns: [ns],
  backend: {
    // Load the bundle from master regardless of which realm the console manages.
    loadPath: joinPath(environment.adminBaseUrl, `resources/${ns}/admin/{{lng}}`),
    parse: (data: string) => {
      const messages = JSON.parse(data) as KeyValue[];
      return Object.fromEntries(messages.map(({ key, value }) => [key, value]));
    },
  },
});

i18n.use(FetchBackend);
i18n.use(initReactI18next);
