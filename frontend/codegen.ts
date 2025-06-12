// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { CodegenConfig } from "@graphql-codegen/cli";

const config: CodegenConfig = {
  schema: "./schema.graphql",
  documents: ["src/**/*.{tsx,ts}", "!src/gql/**/*"],
  ignoreNoDocuments: true, // for better experience with the watcher
  generates: {
    "./src/gql/": {
      preset: "client",
      plugins: ["typescript-msw"],
      config: {
        documentMode: "string",
        useTypeImports: true,
        enumsAsTypes: true,
        // By default, unknown scalars are generated as `any`. This is not ideal for catching potential bugs.
        defaultScalarType: "unknown",
        maybeValue: "T | null | undefined",
        scalars: {
          DateTime: "string",
          Url: "string",
        },
      },
    },
  },
};

export default config;
