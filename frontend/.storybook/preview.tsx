// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type {
  ArgTypes,
  Decorator,
  Parameters,
  Preview,
} from "@storybook/react-vite";
import { TooltipProvider } from "@vector-im/compound-web";
import { initialize, mswLoader } from "msw-storybook-addon";
import { useLayoutEffect } from "react";
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

export const parameters: Parameters = {
  controls: {
    matchers: {
      color: /(background|color)$/i,
      date: /Date$/,
    },
  },
};

export const globalTypes = {
  theme: {
    name: "Theme",
    defaultValue: "system",
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
} satisfies ArgTypes;

const allThemesClasses = globalTypes.theme.toolbar.items.map(
  ({ value }) => `cpd-theme-${value}`,
);

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

export const decorators: Decorator[] = [
  withThemeProvider,
  withDummyRouter,
  withTooltipProvider,
];

const locales = Object.fromEntries(
  localazyMetadata.languages.map(({ language, name, localizedName }) => [
    language,
    `${localizedName} (${name})`,
  ]),
);

const preview: Preview = {
  initialGlobals: {
    locale: localazyMetadata.baseLocale,
    locales,
  },
  parameters: {
    i18n,
  },
  loaders: [mswLoader],
  tags: ["autodocs"],
};

export default preview;
