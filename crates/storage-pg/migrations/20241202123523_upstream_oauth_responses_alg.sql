-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add columns to upstream_oauth_providers to specify the
-- expected signing algorithm for the endpoint JWT responses.
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "id_token_signed_response_alg" TEXT NOT NULL DEFAULT 'RS256',
  ADD COLUMN "userinfo_signed_response_alg" TEXT;
