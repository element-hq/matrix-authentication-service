// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";
import zlib from "node:zlib";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import react from "@vitejs/plugin-react";
import browserslistToEsbuild from "browserslist-to-esbuild";
import { globSync } from "tinyglobby";
import type { Manifest, PluginOption } from "vite";
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

// Pre-compress the assets, so that the server can serve them directly
function compression(): PluginOption {
  const gzip = promisify(zlib.gzip);
  const brotliCompress = promisify(zlib.brotliCompress);

  return {
    name: "asset-compression",
    apply: "build",
    enforce: "post",

    async generateBundle(_outputOptions, bundle) {
      const promises = Object.entries(bundle).flatMap(
        ([fileName, assetOrChunk]) => {
          const source =
            assetOrChunk.type === "asset"
              ? assetOrChunk.source
              : assetOrChunk.code;

          // Don't compress empty files, only compress CSS, JS and JSON files
          if (
            !source ||
            !(
              fileName.endsWith(".js") ||
              fileName.endsWith(".css") ||
              fileName.endsWith(".json")
            )
          ) {
            return [];
          }

          const uncompressed = Buffer.from(source);

          // We pre-compress assets with brotli as it offers the best
          // compression ratios compared to even zstd, and gzip as a fallback
          return [
            { compress: gzip, ext: "gz" },
            { compress: brotliCompress, ext: "br" },
          ].map(async ({ compress, ext }) => {
            const compressed = await compress(uncompressed);

            this.emitFile({
              type: "asset",
              fileName: `${fileName}.${ext}`,
              source: compressed,
            });
          });
        },
      );

      await Promise.all(promises);
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
      // This uses all the files in the src/entrypoints directory as inputs
      input: globSync(resolve(__dirname, "src/entrypoints/**/*.{css,ts,tsx}")),
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

    compression(),

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
