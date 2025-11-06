// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// @ts-check

/** @type {import('tailwindcss').Config} */

module.exports = {
  mode: "jit",
  content: ["./src/**/*.tsx", "./index.html", "../templates/**/*.html"],
  theme: {
    colors: {
      white: "#FFFFFF",
      primary: "var(--cpd-color-text-primary)",
      secondary: "var(--cpd-color-text-secondary)",
      critical: "var(--cpd-color-text-critical-primary)",
      alert: "#FF5B55",
      links: "#0086E6",
      "grey-25": "#F4F6FA",
      "grey-50": "#E3E8F0",
      "grey-100": "#C1C6CD",
      "grey-150": "#8D97A5",
      "grey-200": "#737D8C",
      "grey-250": "#A9B2BC",
      "grey-300": "#8E99A4",
      "grey-400": "#6F7882",
      "grey-450": "#394049",
    },
    fontWeight: {
      semibold: "var(--cpd-font-weight-semibold)",
      medium: "var(--cpd-font-weight-medium)",
      regular: "var(--cpd-font-weight-regular)",
    },
  },
  variants: {
    extend: {},
  },
  plugins: [],
};
