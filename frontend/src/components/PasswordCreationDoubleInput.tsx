// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Form, Progress } from "@vector-im/compound-web";
import { useDeferredValue, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import type { PasswordComplexity } from "../utils/password_complexity";

// This will load the password complexity module lazily,
// so that it doesn't block the initial render and can be code-split
const loadPromise = import("../utils/password_complexity").then(
  ({ estimatePasswordComplexity }) => estimatePasswordComplexity,
);

const usePasswordComplexity = (password: string): PasswordComplexity => {
  const { t } = useTranslation();
  const [result, setResult] = useState<PasswordComplexity>({
    score: 0,
    scoreText: t("frontend.password_strength.placeholder"),
    improvementsText: [],
  });
  const deferredPassword = useDeferredValue(password);

  useEffect(() => {
    if (deferredPassword === "") {
      setResult({
        score: 0,
        scoreText: t("frontend.password_strength.placeholder"),
        improvementsText: [],
      });
    } else {
      loadPromise
        .then((estimatePasswordComplexity) =>
          estimatePasswordComplexity(deferredPassword, t),
        )
        .then((response) => setResult(response));
    }
  }, [deferredPassword, t]);

  return result;
};

export default function PasswordCreationDoubleInput({
  minimumPasswordComplexity,
  forceShowNewPasswordInvalid,
}: {
  minimumPasswordComplexity: number;
  forceShowNewPasswordInvalid: boolean;
}): React.ReactElement {
  const { t } = useTranslation();
  const newPasswordRef = useRef<HTMLInputElement>(null);
  const newPasswordAgainRef = useRef<HTMLInputElement>(null);
  const [newPassword, setNewPassword] = useState("");

  const passwordComplexity = usePasswordComplexity(newPassword);
  let passwordStrengthTint: "red" | "orange" | "lime" | "green" | undefined;
  if (newPassword === "") {
    passwordStrengthTint = undefined;
  } else {
    passwordStrengthTint = (["red", "red", "orange", "lime", "green"] as const)[
      passwordComplexity.score
    ];
  }

  return (
    <>
      <Form.Field name="new_password">
        <Form.Label>
          {t("frontend.password_change.new_password_label")}
        </Form.Label>

        <Form.PasswordControl
          required
          autoComplete="new-password"
          ref={newPasswordRef}
          onBlur={() =>
            newPasswordAgainRef.current?.value &&
            newPasswordAgainRef.current?.reportValidity()
          }
          onChange={(e) => setNewPassword(e.target.value)}
        />

        <Progress
          size="sm"
          getValueLabel={() => passwordComplexity.scoreText}
          tint={passwordStrengthTint}
          max={4}
          value={passwordComplexity.score}
        />

        {passwordComplexity.improvementsText.map((suggestion) => (
          <Form.HelpMessage key={suggestion}>{suggestion}</Form.HelpMessage>
        ))}

        {passwordComplexity.score < minimumPasswordComplexity && (
          <Form.ErrorMessage match={() => true}>
            {t("frontend.password_strength.too_weak")}
          </Form.ErrorMessage>
        )}

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
