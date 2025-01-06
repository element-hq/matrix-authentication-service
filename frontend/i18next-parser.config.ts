// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import type { UserConfig } from "i18next-parser";

export default {
  keySeparator: ".",
  pluralSeparator: ":",
  defaultNamespace: "frontend",
  lexers: {
    ts: [
      {
        lexer: "JavascriptLexer",
        functions: ["t"],
        namespaceFunctions: ["useTranslation", "withTranslation"],
      },
    ],
    tsx: [
      {
        lexer: "JsxLexer",
        functions: ["t"],
        namespaceFunctions: ["useTranslation", "withTranslation"],
      },
    ],
  },
  locales: ["en"],
  output: "locales/$LOCALE.json",
  input: ["src/**/*.{ts,tsx}"],
  sort: true,
} satisfies UserConfig;
