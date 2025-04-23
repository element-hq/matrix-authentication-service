-- Copyright 2024, 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

INSERT INTO access_tokens
  (
  id,
  user_id,
  device_id,
  token,
  puppets_user_id
  )
  VALUES
  (
  42,
  '@alice:example.com',
  NULL,
  'syt_pupupupupup_eett',
  '@bob:example.com'
  );
