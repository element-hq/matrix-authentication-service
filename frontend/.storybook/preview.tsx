// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { Decorator, Preview } from "@storybook/react-vite";
import { TooltipProvider } from "@vector-im/compound-web";
import { initialize, mswLoader } from "msw-storybook-addon";
import { useEffect, useLayoutEffect } from "react";
import { I18nextProvider } from "react-i18next";
import "../src/shared.css";
import i18n, { setupI18n } from "../src/i18n";
import { DummyRouter } from "../src/test-utils/router";
import { handlers } from "../tests/mocks/handlers";
import localazyMetadata from "./locales";

initialize(
  {
    onUnhandledRequest: "bypass",
    serviceWorker: {
      url: "./mockServiceWorker.js",
    },
  },
  handlers,
);

setupI18n();

const allThemesClasses = [
  "cpd-theme-light",
  "cpd-theme-light-hc",
  "cpd-theme-dark",
  "cpd-theme-dark-hc",
];

const ThemeSwitcher: React.FC<{
  theme: string;
}> = ({ theme }) => {
  useLayoutEffect(() => {
    document.documentElement.classList.remove(...allThemesClasses);
    if (theme !== "system") {
      document.documentElement.classList.add(`cpd-theme-${theme}`);
    }
    return () => document.documentElement.classList.remove(...allThemesClasses);
  }, [theme]);

  return null;
};

const withThemeProvider: Decorator = (Story, context) => {
  return (
    <>
      <ThemeSwitcher theme={context.globals.theme} />
      <Story />
    </>
  );
};

const LocaleSwitcher: React.FC<{
  locale: string;
}> = ({ locale }) => {
  useEffect(() => {
    i18n.changeLanguage(locale);
  }, [locale]);

  return null;
};

const withI18nProvider: Decorator = (Story, context) => {
  return (
    <>
      <LocaleSwitcher locale={context.globals.locale} />
      <I18nextProvider i18n={i18n}>
        <Story />
      </I18nextProvider>
    </>
  );
};

const withDummyRouter: Decorator = (Story, _context) => {
  return (
    <DummyRouter>
      <Story />
    </DummyRouter>
  );
};

const withTooltipProvider: Decorator = (Story, _context) => {
  return (
    <TooltipProvider>
      <Story />
    </TooltipProvider>
  );
};

const preview: Preview = {
  loaders: [mswLoader],
  parameters: {
    controls: {
      matchers: {
        color: /(background|color)$/i,
        date: /Date$/,
      },
    },
  },
  decorators: [
    withI18nProvider,
    withThemeProvider,
    withDummyRouter,
    withTooltipProvider,
  ],
  globalTypes: {
    theme: {
      name: "Theme",
      description: "Global theme for components",
      toolbar: {
        icon: "circlehollow",
        title: "Theme",
        items: [
          { title: "System", value: "system", icon: "browser" },
          { title: "Light", value: "light", icon: "sun" },
          { title: "Light (high contrast)", value: "light-hc", icon: "sun" },
          { title: "Dark", value: "dark", icon: "moon" },
          { title: "Dark (high contrast)", value: "dark-hc", icon: "moon" },
        ],
      },
    },

    locale: {
      name: "Locale",
      description: "Locale for the app",
      toolbar: {
        title: "Language",
        icon: "globe",
        items: localazyMetadata.languages.map(
          ({ language, localizedName, name }) => ({
            title: `${localizedName} (${name})`,
            value: language,
          }),
        ),
      },
    },
  },
  initialGlobals: {
    locale: localazyMetadata.baseLocale,
    theme: "system",
  },
  tags: ["autodocs"],
};

export default preview;
