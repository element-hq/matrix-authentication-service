// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { Form, Progress } from "@vector-im/compound-web";
import { useTranslation } from "react-i18next";

import { usePasswordComplexity } from "../utils/usePasswordComplexity";

const TINTS = ["red", "red", "orange", "lime", "green"] as const;

/**
 * Strength meter, improvement hints and too-weak error for a new password.
 * Renders as a set of `Form.Field` children, so it must be used inside one.
 */
const PasswordComplexityFeedback: React.FC<{
  password: string;
  minimumPasswordComplexity: number;
}> = ({ password, minimumPasswordComplexity }) => {
  const { t } = useTranslation();
  const complexity = usePasswordComplexity(password);

  return (
    <>
      <Progress
        size="sm"
        getValueLabel={() => complexity.scoreText}
        tint={password === "" ? undefined : TINTS[complexity.score]}
        max={4}
        value={complexity.score}
      />

      {complexity.improvementsText.map((suggestion) => (
        <Form.HelpMessage key={suggestion}>{suggestion}</Form.HelpMessage>
      ))}

      {complexity.score < minimumPasswordComplexity && (
        <Form.ErrorMessage match={() => true}>
          {t("frontend.password_strength.too_weak")}
        </Form.ErrorMessage>
      )}
    </>
  );
};

export default PasswordComplexityFeedback;
