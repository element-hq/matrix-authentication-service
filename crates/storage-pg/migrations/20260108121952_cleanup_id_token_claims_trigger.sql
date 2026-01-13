-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- When we introduced an id_token_claims column on upstream OAuth 2.0 logins, we
-- added a trigger to make sure that when rolling back the new columns gets
-- automatically filled correctly. It's been a while, it's safe to remove them.
-- https://github.com/element-hq/matrix-authentication-service/pull/4743
DROP TRIGGER IF EXISTS trg_fill_id_token_claims ON upstream_oauth_authorization_sessions;
DROP FUNCTION IF EXISTS fill_id_token_claims();
