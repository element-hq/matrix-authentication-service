-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Make the nonce column optional on the upstream oauth sessions
ALTER TABLE "upstream_oauth_authorization_sessions"
    ALTER COLUMN "nonce" DROP NOT NULL;
