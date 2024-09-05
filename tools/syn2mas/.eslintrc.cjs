// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

const HEADER_TEMPLATE = `\
// Copyright %%CURRENT_YEAR%% New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

`;

/** @type {import('eslint').Linter.Config} */
module.exports = {
  root: true,
  plugins: ["matrix-org"],
  extends: [
    "plugin:prettier/recommended",
    "plugin:import/recommended",
    "plugin:import/typescript",
    "plugin:matrix-org/typescript",
  ],
  env: {
    browser: false,
    node: true,
  },
  parser: "@typescript-eslint/parser",
  parserOptions: {
    project: "./tsconfig.eslint.json",
  },
  rules: {
    "matrix-org/require-copyright-header": ["error", HEADER_TEMPLATE],
    "import/order": [
      "error",
      {
        "newlines-between": "always",
        alphabetize: { order: "asc" },
      },
    ],
    "@typescript-eslint/no-floating-promises": "error",
    "@typescript-eslint/no-misused-promises": "error",
    "@typescript-eslint/promise-function-async": "error",
    "@typescript-eslint/await-thenable": "error",

    // False-positive because of id128 and log4js
    "import/no-named-as-default-member": "off",
  },
  settings: {
    "import/parsers": {
      "@typescript-eslint/parser": [".ts", ".mts"],
    },
    "import/resolver": {
      typescript: true,
      node: true,
    },
  },
  ignorePatterns: ["dist"],
};
