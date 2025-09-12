// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { tanstackRouter } from "@tanstack/router-plugin/vite";
import react from "@vitejs/plugin-react";
import browserslistToEsbuild from "browserslist-to-esbuild";
import type { Manifest, PluginOption } from "vite";
import compression from "vite-plugin-compression";
import codegen from "vite-plugin-graphql-codegen";
import manifestSRI from "vite-plugin-manifest-sri";
import { defineConfig } from "vitest/config";

function i18nHotReload(): PluginOption {
  return {
    name: "i18n-hot-reload",
    handleHotUpdate({ file, server }): void {
      if (file.includes("locales") && file.endsWith(".json")) {
        console.log("Locale file updated");
        server.hot.send({
          type: "custom",
          event: "locales-update",
        });
      }
    },
  };
}

export default defineConfig((env) => ({
  base: "./",

  css: {
    modules: {
      localsConvention: "camelCaseOnly",
    },
  },

  define: {
    "import.meta.vitest": "undefined",
    "process.env.NODE_ENV": JSON.stringify(env.mode),
  },

  build: {
    manifest: "manifest.json",
    assetsDir: "",
    sourcemap: true,
    target: browserslistToEsbuild(),
    cssCodeSplit: true,

    rollupOptions: {
      input: [
        resolve(__dirname, "src/main.tsx"),
        resolve(__dirname, "src/shared.css"),
        resolve(__dirname, "src/templates.css"),
        resolve(__dirname, "src/swagger.ts"),
      ],
    },
  },

  plugins: [
    codegen(),

    tanstackRouter({
      target: "react",
      autoCodeSplitting: true,
      verboseFileRoutes: false,
    }),

    react(),

    // Custom plugin to make sure that each asset has an entry in the manifest
    // This is needed so that the preloading & asset integrity generation works
    {
      name: "manifest-missing-assets",

      apply: "build",
      enforce: "post",
      writeBundle: {
        // This needs to be executed sequentially before the manifestSRI plugin
        sequential: true,
        order: "pre",
        async handler({ dir }): Promise<void> {
          const manifestPath = resolve(dir, "manifest.json");

          const manifest: Manifest | undefined = await readFile(
            manifestPath,
            "utf-8",
          ).then(JSON.parse, () => undefined);

          if (manifest) {
            const existing: Set<string> = new Set();
            const needs: Set<string> = new Set();

            for (const chunk of Object.values(manifest)) {
              existing.add(chunk.file);
              for (const css of chunk.css ?? []) needs.add(css);
              for (const sub of chunk.assets ?? []) needs.add(sub);
            }

            const missing = Array.from(needs).filter((a) => !existing.has(a));

            if (missing.length > 0) {
              for (const asset of missing) {
                manifest[asset] = {
                  file: asset,
                  integrity: "",
                };
              }

              await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
            }
          }
        },
      },
    },

    manifestSRI(),

    // Pre-compress the assets, so that the server can serve them directly
    compression({
      algorithm: "gzip",
      ext: ".gz",
    }),
    compression({
      algorithm: "brotliCompress",
      ext: ".br",
    }),
    compression({
      algorithm: "deflate",
      ext: ".zz",
    }),

    i18nHotReload(),
  ],

  server: {
    base: "/account/",
    proxy: {
      // Routes mostly extracted from crates/router/src/endpoints.rs
      "^/(|graphql.*|assets.*|\\.well-known.*|oauth2.*|login.*|logout.*|register.*|reauth.*|add-email.*|verify-email.*|change-password.*|consent.*|_matrix.*|complete-compat-sso.*|link.*|device.*|upstream.*|recover.*)$":
        "http://127.0.0.1:8080",
    },
  },

  test: {
    globalSetup: "./vitest.global-setup.ts",
    setupFiles: "./vitest.setup.ts",
    coverage: {
      provider: "v8",
      src: ["./src/"],
      exclude: ["**/gql/**", "**/*.d.ts", "**/*.stories.*"],
      all: true,
      reporter: ["text", "html", "lcov"],
    },
  },
}));
