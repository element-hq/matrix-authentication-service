-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY
  user_session_authentications_user_passkey_id_fk
  ON user_session_authentications (user_passkey_id);
