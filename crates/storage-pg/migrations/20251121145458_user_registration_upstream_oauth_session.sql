-- Copyright 2025 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- Track what upstream OAuth session to associate during user registration
ALTER TABLE user_registrations
    ADD COLUMN upstream_oauth_authorization_session_id UUID
      REFERENCES upstream_oauth_authorization_sessions (upstream_oauth_authorization_session_id)
      ON DELETE SET NULL;

CREATE INDEX user_registrations_upstream_oauth_session_id_idx
    ON user_registrations (upstream_oauth_authorization_session_id);
