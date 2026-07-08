-- Copyright 2026 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Capture the raw query parameters from the downstream OAuth2 authorization
-- request, so the upstream OAuth2 provider authorization handler can
-- reference them from templated `additional_authorization_parameters`.
ALTER TABLE "oauth2_authorization_grants"
    ADD COLUMN "raw_parameters" JSONB;
