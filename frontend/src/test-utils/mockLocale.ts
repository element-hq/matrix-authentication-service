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

  // Vitest 4.x requires function/class implementations for spyOn mocks when
  // mocking constructors. For built-in constructors like Intl.DateTimeFormat
  // that have internal slots, we use a function that returns a new instance.
  // This is valid JavaScript - when a constructor returns an object, that
  // object becomes the instance (instead of `this`).
  function MockDateTimeFormat(
    this: unknown,
    locales?: Intl.LocalesArgument,
    options?: Intl.DateTimeFormatOptions,
  ): Intl.DateTimeFormat {
    // Apply default locale when no locale is specified
    return new OriginalDateTimeFormat(locales || defaultLocale, options);
  }

  // Inherit static methods from the original DateTimeFormat
  Object.setPrototypeOf(MockDateTimeFormat, OriginalDateTimeFormat);
  // Set up prototype chain so instanceof checks work correctly
  Object.setPrototypeOf(
    MockDateTimeFormat.prototype,
    OriginalDateTimeFormat.prototype,
  );

  vi.spyOn(Intl, "DateTimeFormat").mockImplementation(
    MockDateTimeFormat as typeof Intl.DateTimeFormat,
  );
};
