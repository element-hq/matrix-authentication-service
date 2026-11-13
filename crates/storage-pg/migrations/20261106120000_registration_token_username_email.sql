-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- The username and email address a registration with this token must use.
-- NULL leaves the registering user free to choose.
ALTER TABLE "user_registration_tokens"
  ADD COLUMN "username" TEXT,
  ADD COLUMN "email" TEXT;
