// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { KnipConfig } from "knip";

export default {
  entry: ["src/entrypoints/*", "src/routes/*"],
  ignore: ["src/gql/*", ".storybook/locales.ts", "i18next.config.ts"],
} satisfies KnipConfig;
