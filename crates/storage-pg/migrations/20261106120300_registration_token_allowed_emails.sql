-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- The email addresses allowed to register with this token, or NULL for any
ALTER TABLE "user_registration_tokens"
  ADD COLUMN "allowed_emails" TEXT[],
  ADD CONSTRAINT "user_registration_tokens_allowed_emails_check"
    CHECK ("allowed_emails" IS NULL OR (cardinality("allowed_emails") > 0 AND "email" IS NULL));
