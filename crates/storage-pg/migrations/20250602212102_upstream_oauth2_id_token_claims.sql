-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This is the decoded claims from the ID token stored as JSONB
ALTER TABLE upstream_oauth_authorization_sessions
    ADD COLUMN id_token_claims JSONB;
