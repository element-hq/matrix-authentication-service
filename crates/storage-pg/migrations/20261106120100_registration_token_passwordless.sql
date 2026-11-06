-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Whether registrations using this token skip the password step entirely
ALTER TABLE user_registration_tokens
  ADD COLUMN passwordless BOOLEAN NOT NULL DEFAULT FALSE;
