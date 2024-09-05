// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { CodegenConfig } from "@graphql-codegen/cli";

// Adds a comment to the top of generated files to ignore linting and formatting
const lintIgnore = {
  add: {
    content: "/* prettier-ignore */\n/* eslint-disable */",
  },
} as const;

const config: CodegenConfig = {
  schema: "./schema.graphql",
  documents: ["src/**/*.{tsx,ts}", "!src/gql/**/*"],
  ignoreNoDocuments: true, // for better experience with the watcher
  generates: {
    "./src/gql/": {
      preset: "client",
      config: {
        // By default, unknown scalars are generated as `any`. This is not ideal for catching potential bugs.
        defaultScalarType: "unknown",
        scalars: {
          DateTime: "string",
          Url: "string",
        },
      },
      plugins: [lintIgnore],
    },
    "./src/gql/schema.ts": {
      plugins: ["urql-introspection", lintIgnore],
    },
  },
};

export default config;
