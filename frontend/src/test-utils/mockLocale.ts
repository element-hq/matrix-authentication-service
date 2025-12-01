// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { vi } from "vitest";

/**
 * Mock the locale on Intl.DateTimeFormat
 * To achieve stable formatted dates across environments
 * Defaults to `en-GB`
 */
export const mockLocale = (defaultLocale = "en-GB"): void => {
  const OriginalDateTimeFormat = Intl.DateTimeFormat;

  // Vitest 4.x requires function/class implementations for spyOn mocks
  function MockDateTimeFormat(
    this: Intl.DateTimeFormat,
    locales?: Intl.LocalesArgument,
    options?: Intl.DateTimeFormatOptions,
  ): Intl.DateTimeFormat {
    return new OriginalDateTimeFormat(locales || defaultLocale, options);
  }

  // Copy static methods and prototype from original
  Object.setPrototypeOf(MockDateTimeFormat, OriginalDateTimeFormat);
  MockDateTimeFormat.prototype = OriginalDateTimeFormat.prototype;

  vi.spyOn(Intl, "DateTimeFormat").mockImplementation(
    MockDateTimeFormat as typeof Intl.DateTimeFormat,
  );
};
