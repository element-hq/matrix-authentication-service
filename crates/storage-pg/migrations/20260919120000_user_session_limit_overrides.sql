-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

CREATE TABLE user_session_limit_overrides (
    user_session_limit_override_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    oauth2_client_id UUID REFERENCES oauth2_clients (oauth2_client_id) ON DELETE CASCADE,
    soft_limit BIGINT NOT NULL,
    hard_limit BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT user_session_limit_overrides_limits_check
        CHECK (soft_limit > 0 AND hard_limit > 0 AND hard_limit >= soft_limit)
);

-- One global override per user (NULL client) and one override per user+client
CREATE UNIQUE INDEX user_session_limit_overrides_user_global_unique
    ON user_session_limit_overrides (user_id)
    WHERE oauth2_client_id IS NULL;

CREATE UNIQUE INDEX user_session_limit_overrides_user_client_unique
    ON user_session_limit_overrides (user_id, oauth2_client_id)
    WHERE oauth2_client_id IS NOT NULL;

CREATE INDEX user_session_limit_overrides_user_id_idx
    ON user_session_limit_overrides (user_id);
