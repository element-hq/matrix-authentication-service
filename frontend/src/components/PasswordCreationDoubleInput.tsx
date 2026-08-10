// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Form } from "@vector-im/compound-web";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import PasswordComplexityFeedback from "./PasswordComplexityFeedback";

export default function PasswordCreationDoubleInput({
  minimumPasswordComplexity,
  forceShowNewPasswordInvalid = false,
}: {
  minimumPasswordComplexity: number;
  forceShowNewPasswordInvalid?: boolean;
}): React.ReactElement {
  const { t } = useTranslation();
  const newPasswordAgainRef = useRef<HTMLInputElement>(null);
  const [newPassword, setNewPassword] = useState("");

  return (
    <>
      <Form.Field name="new_password">
        <Form.Label>
          {t("frontend.password_change.new_password_label")}
        </Form.Label>

        <Form.PasswordControl
          required
          autoComplete="new-password"
          onBlur={() =>
            newPasswordAgainRef.current?.value &&
            newPasswordAgainRef.current?.reportValidity()
          }
          onChange={(e) => setNewPassword(e.target.value)}
        />

        <PasswordComplexityFeedback
          password={newPassword}
          minimumPasswordComplexity={minimumPasswordComplexity}
        />

        <Form.ErrorMessage match="valueMissing">
          {t("frontend.errors.field_required")}
        </Form.ErrorMessage>

        {forceShowNewPasswordInvalid && (
          <Form.ErrorMessage>
            {t(
              "frontend.password_change.failure.description.invalid_new_password",
            )}
          </Form.ErrorMessage>
        )}
      </Form.Field>

      <Form.Field name="new_password_again">
        {/*
        TODO This field has validation defects,
        some caused by Radix-UI upstream bugs.
        https://github.com/matrix-org/matrix-authentication-service/issues/2855
      */}
        <Form.Label>
          {t("frontend.password_change.new_password_again_label")}
        </Form.Label>

        <Form.PasswordControl
          required
          ref={newPasswordAgainRef}
          autoComplete="new-password"
        />

        <Form.ErrorMessage match="valueMissing">
          {t("frontend.errors.field_required")}
        </Form.ErrorMessage>

        <Form.ErrorMessage match={(v, form) => v !== form.get("new_password")}>
          {t("frontend.password_change.passwords_no_match")}
        </Form.ErrorMessage>

        <Form.SuccessMessage match="valid">
          {t("frontend.password_change.passwords_match")}
        </Form.SuccessMessage>
      </Form.Field>
    </>
  );
}
