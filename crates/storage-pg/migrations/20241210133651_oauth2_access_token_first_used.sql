-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Track when the access token was first used. A NULL value means it was never used.
ALTER TABLE oauth2_access_tokens
  ADD COLUMN "first_used_at" TIMESTAMP WITH TIME ZONE;
