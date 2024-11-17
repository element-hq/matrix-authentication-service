// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { StorybookConfig } from "@storybook/react-vite";

const config: StorybookConfig = {
  stories: ["../{src,stories}/**/*.stories.@(js|jsx|ts|tsx)"],

  addons: [
    // Automatic docs pages
    "@storybook/addon-docs",

    // Controls of components props
    "@storybook/addon-controls",

    // Document components actions
    "@storybook/addon-actions",

    // Helps measuring elements
    "@storybook/addon-measure",

    // Helps showing components boundaries
    "@storybook/addon-outline",

    // Quickly change viewport size
    "@storybook/addon-viewport",

    // Theme switch toolbar
    "@storybook/addon-toolbars",

    // Interactions
    "@storybook/addon-interactions",

    // i18next integration
    "storybook-react-i18next",
  ],

  framework: "@storybook/react-vite",

  typescript: {
    reactDocgen: "react-docgen-typescript",
  },

  core: {
    disableTelemetry: true,
  },

  docs: {
    autodocs: true,
  },

  env: {
    STORYBOOK: "true",
  },

  viteFinal: async (config) => {
    // Host all the assets in the root directory,
    // so that the service worker is correctly scoped to the root
    config.build.assetsDir = "";
    return config;
  },
};

export default config;
