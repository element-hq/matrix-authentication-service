-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This backfills the id_token_claims column in the upstream_oauth_authorization_sessions table
-- by decoding the id_token column and storing the decoded claims in the id_token_claims column.
UPDATE upstream_oauth_authorization_sessions
SET id_token_claims = CASE
    WHEN id_token IS NULL OR id_token = '' THEN NULL
    WHEN split_part(id_token, '.', 2) = '' THEN NULL
    ELSE
        (convert_from(
            decode(
                replace(replace(split_part(id_token, '.', 2), '-', '+'), '_', '/') ||
                repeat('=', (4 - length(split_part(id_token, '.', 2)) % 4) % 4),
                'base64'
            ),
            'UTF8'
        ))::JSONB
END
WHERE id_token IS NOT NULL AND id_token_claims IS NULL;
