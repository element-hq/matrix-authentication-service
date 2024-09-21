// @ts-check

import js from "@eslint/js";
import eslintPluginImportX from "eslint-plugin-import-x";
import eslintConfigPrettier from "eslint-config-prettier";
import reactPlugin from "eslint-plugin-react";
import globals from "globals";
import tseslint from "typescript-eslint";
import jsxA11y from "eslint-plugin-jsx-a11y";

export default tseslint.config(
  js.configs.recommended,
  eslintConfigPrettier,
  eslintPluginImportX.flatConfigs.recommended,
  eslintPluginImportX.flatConfigs.react,
  eslintPluginImportX.flatConfigs.typescript,
  jsxA11y.flatConfigs.recommended,
  ...tseslint.configs.recommended,
  reactPlugin.configs.flat.recommended,
  reactPlugin.configs.flat["jsx-runtime"],
  {
    ignores: [
      "**/dist/**/*",
      "**/__generated__/**/*",
      "**/coverage/**/*",
      "!.storybook/locales.ts",
      "*/gql/*.ts",
    ],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      ...reactPlugin.configs.flat.recommended.languageOptions,
      globals: {
        ...globals.browser,
      },
    },
    rules: {
      "import-x/order": "error",
    },
  },
);
