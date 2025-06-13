// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import * as i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { afterEach, beforeEach } from "vitest";

import EN from "./locales/en.json";

beforeEach(() => {
  i18n.use(initReactI18next).init({
    fallbackLng: "en",
    keySeparator: ".",
    pluralSeparator: ":",
    interpolation: {
      escapeValue: false, // React has built-in XSS protections
    },
    lng: "en",
    resources: {
      en: {
        translation: EN,
      },
    },
  });
});

afterEach(() => cleanup());
