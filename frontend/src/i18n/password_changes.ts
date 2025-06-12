// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import type { TFunction } from "i18next";

import type { SetPasswordStatus } from "../gql/graphql";

/**
 * Provides a translated string representing a `SetPasswordStatus`.
 *
 * Returns the translated string, or undefined if a translated string is not shown at the
 * top-level of a password change form for this status.
 *
 * The form is responsible for showing the following errors itself, inline with the form field:
 * - `WrongPassword`
 * - `InvalidNewPassword`
 *
 * Throws an error if the status is not known.
 */
export function translateSetPasswordError(
  t: TFunction,
  status: SetPasswordStatus | undefined,
): string | undefined {
  switch (status) {
    case "NO_CURRENT_PASSWORD":
      return t(
        "frontend.password_change.failure.description.no_current_password",
      );
    case "PASSWORD_CHANGES_DISABLED":
      return t(
        "frontend.password_change.failure.description.password_changes_disabled",
      );
    case "ACCOUNT_LOCKED":
      return t("frontend.password_change.failure.description.account_locked");
    case "EXPIRED_RECOVERY_TICKET":
      return t(
        "frontend.password_change.failure.description.expired_recovery_ticket",
      );
    case "NO_SUCH_RECOVERY_TICKET":
      return t(
        "frontend.password_change.failure.description.no_such_recovery_ticket",
      );
    case "RECOVERY_TICKET_ALREADY_USED":
      return t(
        "frontend.password_change.failure.description.recovery_ticket_already_used",
      );

    case "WRONG_PASSWORD":
    case "INVALID_NEW_PASSWORD":
      // These cases are shown as inline errors in the form itself.
      return undefined;

    case "ALLOWED":
    case undefined:
      return undefined;

    default:
      throw new Error(`unexpected error when changing password: ${status}`);
  }
}
