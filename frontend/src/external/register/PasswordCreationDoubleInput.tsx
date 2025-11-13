// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Form, Progress } from "@vector-im/compound-web";
import { useDeferredValue, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { type FragmentType, graphql, useFragment } from "../../gql";
import type { PasswordComplexity } from "../../utils/password_complexity";

const CONFIG_FRAGMENT = graphql(/* GraphQL */ `
  fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {
    id
    minimumPasswordComplexity
  }
`);

// This will load the password complexity module lazily,
// so that it doesn't block the initial render and can be code-split
const loadPromise = import("../../utils/password_complexity").then(
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

//:tchap: this compoenent has been duplicated from src/frontend/components/PasswordCreationDoubleInput
//:tchap: it should be reusing this component with possibilities to customize names and labels
export default function PasswordCreationDoubleInput({
  siteConfig,
  forceShowNewPasswordInvalid,
}: {
  siteConfig: FragmentType<typeof CONFIG_FRAGMENT>;
  forceShowNewPasswordInvalid: boolean;
}): React.ReactElement {
  const { t } = useTranslation();
  const { minimumPasswordComplexity } = useFragment(
    CONFIG_FRAGMENT,
    siteConfig,
  );

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
      <Form.Field name="password">
        <Form.Label>{t("common.password")}</Form.Label>

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

      <Form.Field name="password_confirm">
        {/*
        TODO This field has validation defects,
        some caused by Radix-UI upstream bugs.
        https://github.com/matrix-org/matrix-authentication-service/issues/2855
      */}
        <Form.Label>{t("common.password_confirm")}</Form.Label>

        <Form.PasswordControl
          required
          ref={newPasswordAgainRef}
          autoComplete="new-password"
        />

        <Form.ErrorMessage match="valueMissing">
          {t("frontend.errors.field_required")}
        </Form.ErrorMessage>

        <Form.ErrorMessage match={(v, form) => v !== form.get("password")}>
          {t("frontend.password_change.passwords_no_match")}
        </Form.ErrorMessage>

        <Form.SuccessMessage match="valid">
          {t("frontend.password_change.passwords_match")}
        </Form.SuccessMessage>
      </Form.Field>
    </>
  );
}
