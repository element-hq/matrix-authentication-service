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
  refresh_token_id,
  used
  )
  VALUES
  (
    42,
    '@alice:example.com',
    'ADEVICE',
    'syt_aaaaaaaaaaaaaa_aaaa',
    7,
    TRUE
  ),
  (
    43,
    '@alice:example.com',
    'ADEVICE',
    'syt_AAAAAAAAAAAAAA_AAAA',
    8,
    TRUE
  );

INSERT INTO refresh_tokens
  (
  id,
  user_id,
  device_id,
  token,
  next_token_id,
  expiry_ts,
  ultimate_session_expiry_ts
  )
  VALUES
  (
    7,
    '@alice:example.com',
    'ADEVICE',
    'syr_bbbbbbbbbbbbb_bbbb',
    8,
    1738096199000,
    1778096199000
  ),
  (
    8,
    '@alice:example.com',
    'ADEVICE',
    'syr_cccccccccccc_cccc',
    NULL,
    1748096199000,
    1778096199000
  );
