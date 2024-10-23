// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import "i18next";
import type translation from "../../locales/en.json";

declare module "i18next" {
  interface CustomTypeOptions {
    keySeparator: ".";
    pluralSeparator: ":";
    defaultNS: "translation";
    resources: {
      translation: typeof translation;
    };
  }
}
