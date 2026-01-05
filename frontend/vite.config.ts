// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { type FileHandle, open } from "node:fs/promises";
import path, { resolve } from "node:path";
import zlib from "node:zlib";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import react from "@vitejs/plugin-react";
import browserslistToEsbuild from "browserslist-to-esbuild";
import { globSync } from "tinyglobby";
import type { Manifest, PluginOption } from "vite";
import codegen from "vite-plugin-graphql-codegen";
import { defineConfig } from "vitest/config";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

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
  return {
    name: "asset-compression",
    apply: "build",
    enforce: "post",

    writeBundle: {
      // We need to run after Vite's plugins, as it will do some final touches
      // to the files in this phase
      order: "post",
      async handler({ dir }, bundle) {
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
              { compressor: zlib.createGzip(), ext: "gz" },
              {
                compressor: zlib.createBrotliCompress({
                  params: {
                    [zlib.constants.BROTLI_PARAM_MODE]:
                      zlib.constants.BROTLI_MODE_TEXT,
                    // 10 yields better results and is quicker than 11
                    [zlib.constants.BROTLI_PARAM_QUALITY]: 10,
                    [zlib.constants.BROTLI_PARAM_SIZE_HINT]:
                      uncompressed.length,
                  },
                }),
                ext: "br",
              },
            ].map(async ({ compressor, ext }) => {
              const output = path.join(dir, `${fileName}.${ext}`);
              const readStream = Readable.from(uncompressed);
              const writeStream = createWriteStream(output);

              await pipeline(readStream, compressor, writeStream);
            });
          },
        );

        await Promise.all(promises);
      },
    },
  };
}

declare module "vite" {
  interface ManifestChunk {
    integrity: string;
  }
}

// Custom plugin to make sure that each asset has an entry in the manifest
// This is needed so that the preloading & asset integrity generation works
// It also calculates integrity hashes for the assets
function augmentManifest(): PluginOption {
  return {
    name: "augment-manifest",
    apply: "build",
    enforce: "post",

    async writeBundle({ dir }, bundle): Promise<void> {
      const hashes: Record<string, Promise<string>> = {};
      for (const [fileName, assetOrChunk] of Object.entries(bundle)) {
        // Start calculating hash of the asset. We can let that run in the
        // background
        const source =
          assetOrChunk.type === "asset"
            ? assetOrChunk.source
            : assetOrChunk.code;

        hashes[fileName] = (async (): Promise<string> => {
          const digest = await crypto.subtle.digest(
            "SHA-384",
            Buffer.from(source),
          );
          return `sha384-${Buffer.from(digest).toString("base64")}`;
        })();
      }

      const manifestPath = resolve(dir, "manifest.json");

      let manifestHandle: FileHandle;
      try {
        manifestHandle = await open(manifestPath, "r+");
      } catch (error) {
        // Manifest does not exist, nothing to do but still warn about
        this.warn(`Failed to open manifest at ${manifestPath}: ${error}`);
        return;
      }
      const rawManifest = await manifestHandle.readFile("utf-8");
      const manifest = JSON.parse(rawManifest) as Manifest;

      const existing: Set<string> = new Set();
      const needs: Set<string> = new Set();

      for (const chunk of Object.values(manifest)) {
        existing.add(chunk.file);
        chunk.integrity = await hashes[chunk.file];
        for (const css of chunk.css ?? []) needs.add(css);
        for (const sub of chunk.assets ?? []) needs.add(sub);
      }

      const missing = Array.from(needs).filter((a) => !existing.has(a));

      for (const asset of missing) {
        manifest[asset] = {
          file: asset,
          integrity: await hashes[asset],
        };
      }

      // Overwrite the manifest with the augmented entries
      // XXX: you'd think that doing `manifestHandle.writeFile` would work, as
      // the docs says that it 'overwrites the file if it exists'. Turns out, it
      // reuses the previous position from `readFile`, so that would append on
      // the existing, so we have to use `write` with an explicit position.
      // Truncating the file just in case the output is smaller than before.
      await manifestHandle.truncate(0);
      await manifestHandle.write(JSON.stringify(manifest, null, 2), 0, "utf-8");
      await manifestHandle.close();
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
    reportCompressedSize: false,

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

    augmentManifest(),

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
