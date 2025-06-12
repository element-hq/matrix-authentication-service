// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { StorybookConfig } from "@storybook/react-vite";

const config: StorybookConfig = {
  stories: ["../{src,stories}/**/*.stories.@(js|jsx|ts|tsx)"],

  addons: ["storybook-react-i18next", "@storybook/addon-docs"],

  framework: "@storybook/react-vite",

  typescript: {
    reactDocgen: "react-docgen-typescript",
  },

  core: {
    disableTelemetry: true,
  },

  env: {
    STORYBOOK: "true",
  },

  viteFinal: async (config) => {
    // Serve the storybook-specific assets, which has the service worker
    config.publicDir = ".storybook/public";
    return config;
  },
};

export default config;
