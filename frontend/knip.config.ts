// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { KnipConfig } from "knip";

export default {
  entry: [
    "src/main.tsx",
    "src/swagger.tsx",
    "src/routes/*",
    "i18next-parser.config.ts",
  ],
  ignore: ["src/gql/*", "src/routeTree.gen.ts", ".storybook/locales.ts"],
  ignoreDependencies: [
    // This is used by the tailwind PostCSS plugin, but not detected by knip
    "postcss-nesting",
    // We're using @storybook/addon-essentials to simplify upgrades, but knip doesn't detect them
    "@storybook/addon-*",
  ],
} satisfies KnipConfig;
