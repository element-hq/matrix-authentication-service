-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Adds a `registration_token_required` column to the UpstreamOauthProvider table

ALTER TABLE upstream_oauth_providers
  ADD COLUMN registration_token_required BOOLEAN NOT NULL DEFAULT FALSE;