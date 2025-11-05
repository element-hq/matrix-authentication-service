import { resolve } from "node:path";
import { defineConfig, mergeConfig } from "vite";
import viteConfig from "../vite.config";

export default defineConfig((env) =>
  mergeConfig(
    viteConfig(env),
    defineConfig({
      //tchap config
      build: {
        rollupOptions: {
          input: [
            resolve(__dirname, "css/tchap.css"),
            resolve(__dirname, "css/base.css"),
            //resolve(__dirname, "../node_modules/@gouvfr-lasuite/integration/dist/css/prefixed-dsfr.css"),
            resolve(
              __dirname,
              "../node_modules/@gouvfr-lasuite/integration/dist/css/homepage-full.css",
            ),
            resolve(__dirname, "../src/external/View.tsx"),
          ],
        },
      },
    }),
  ),
);
