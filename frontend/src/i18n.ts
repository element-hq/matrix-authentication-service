// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import {
  type BackendModule,
  type InitOptions,
  default as i18n,
  type LanguageDetectorModule,
  type ReadCallback,
  type ResourceKey,
} from "i18next";
import { initReactI18next } from "react-i18next";

// This generates a map of locale names to a function which loads them, which looks like this:
// {
//   "../locales/en.json": () => import("/whatever/assets/root/en-aabbcc.js"),
//   ...
// }
const locales = import.meta.glob<ResourceKey>("../locales/*.json", {
  import: "default",
});

const supportedLngs = Object.keys(locales).map((path) => {
  const lang = path.match(/\/([^/]+)\.json$/)?.[1];
  if (!lang) {
    throw new Error(`Could not parse locale path ${path}`);
  }
  return lang;
});

// A simple language detector that reads the `lang` attribute from the HTML tag
const LanguageDetector = {
  type: "languageDetector",

  detect(): string | undefined {
    const htmlTag =
      typeof document !== "undefined" ? document.documentElement : null;

    if (htmlTag && typeof htmlTag.getAttribute === "function") {
      return htmlTag.getAttribute("lang") || undefined;
    }
  },
} satisfies LanguageDetectorModule;

// A backend that lazily imports the locale files through the loaders generated
// by the glob above.
const Backend = {
  type: "backend",
  init(): void {},
  read(language: string, _namespace: string, callback: ReadCallback): void {
    (async (): Promise<ResourceKey> => {
      const loader = locales[`../locales/${language}.json`];
      if (!loader) {
        throw new Error(`Locale ${language} not found`);
      }

      // XXX: we don't check the JSON shape here, which should be fine
      return await loader();
    })().then(
      (data) => callback(null, data),
      (error) => callback(error, null),
    );
  },
} satisfies BackendModule;

export const setupI18n = () => {
  i18n
    .use(Backend)
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
      fallbackLng: "en",
      keySeparator: ".",
      pluralSeparator: ":",
      defaultNS: "translation",
      supportedLngs,
      interpolation: {
        escapeValue: false, // React has built-in XSS protections
      },
    } satisfies InitOptions);
};

export default i18n;
