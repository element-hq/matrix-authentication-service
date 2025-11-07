// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { defineConfig } from "i18next-cli";

export default defineConfig({
  locales: ["en"],
  extract: {
    input: "src/**/*.{ts,tsx}",
    output: "locales/{{language}}.json",
    defaultNS: false,
    pluralSeparator: ":",
    keySeparator: ".",
    sort: true,
  },
});
