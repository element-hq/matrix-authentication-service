// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { KnipConfig } from "knip";

export default {
  entry: ["src/main.tsx", "src/swagger.ts", "src/routes/*"],
  //:tchap: add tchap vite
  ignore: [
    "src/gql/*",
    "src/routeTree.gen.ts",
    ".storybook/locales.ts",
    "tchap/vite.tchap.config.ts",
  ],
  //:tchap: end
  ignoreDependencies: [
    // This is used by the tailwind PostCSS plugin, but not detected by knip
    "postcss-nesting",
  ],
} satisfies KnipConfig;
