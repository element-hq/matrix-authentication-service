-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add optional username and email columns to registration tokens,
-- allowing admins to provision tokens that pre-fill these fields.
ALTER TABLE "user_registration_tokens"
  ADD COLUMN "username" TEXT,
  ADD COLUMN "email" TEXT;
