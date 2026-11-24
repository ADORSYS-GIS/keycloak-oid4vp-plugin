import { createInstance } from "i18next";
import FetchBackend from "i18next-fetch-backend";
import { initReactI18next } from "react-i18next";
import { environment } from "./environment";
import { joinPath } from "./utils/joinPath";

type KeyValue = { key: string; value: string };

export const i18n = createInstance({
  fallbackLng: "en",
  keySeparator: ".",
  nsSeparator: false,
  interpolation: {
    escapeValue: false,
  },
  defaultNS: [environment.realm],
  ns: [environment.realm],
  backend: {
    // Aggregated theme message bundle for the realm's admin theme.
    loadPath: joinPath(
      environment.adminBaseUrl,
      `resources/{{ns}}/admin/{{lng}}`,
    ),
    parse: (data: string) => {
      const messages = JSON.parse(data) as KeyValue[];
      return Object.fromEntries(messages.map(({ key, value }) => [key, value]));
    },
  },
});

i18n.use(FetchBackend);
i18n.use(initReactI18next);
