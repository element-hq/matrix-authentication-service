// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

/** Compute what the date was 90 days ago, rouding down to the start of the day */
export const getNinetyDaysAgo = (): string => {
  const date = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
  // Round down to the start of the day to avoid rerendering/requerying
  date.setHours(0, 0, 0, 0);
  return date.toISOString();
};
