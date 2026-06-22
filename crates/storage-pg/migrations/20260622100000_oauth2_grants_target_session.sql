-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Records the resolved outcome of verifying a hint on the authorization
-- request: the target user and a user session.
ALTER TABLE oauth2_authorization_grants
  ADD COLUMN target_user_id UUID
    REFERENCES users (user_id),
  ADD COLUMN target_user_session_id UUID
    REFERENCES user_sessions (user_session_id)
    ON DELETE SET NULL;
