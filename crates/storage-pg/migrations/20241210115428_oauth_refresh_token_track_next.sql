-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a reference to the 'next' refresh token when it was consumed and replaced
ALTER TABLE oauth2_refresh_tokens
  ADD COLUMN "next_oauth2_refresh_token_id" UUID
    REFERENCES oauth2_refresh_tokens (oauth2_refresh_token_id);
