// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

import { useDeferredValue, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import type { PasswordComplexity } from "./password_complexity";

// This will load the password complexity module lazily,
// so that it doesn't block the initial render and can be code-split
const loadPromise = import("./password_complexity").then(
  ({ estimatePasswordComplexity }) => estimatePasswordComplexity,
);

/** Score the given password, off the critical path and off the main thread. */
export const usePasswordComplexity = (password: string): PasswordComplexity => {
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
