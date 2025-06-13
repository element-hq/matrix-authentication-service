-- Copyright 2024, 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE files in the repository root for full details.

INSERT INTO devices
  (
    user_id,
    device_id,
    display_name,
    last_seen,
    ip,
    user_agent,
    hidden
  )
  VALUES
  (
    '@alice:example.com',
    'ADEVICE',
    'Matrix Console',
    1623366000000,
    '203.0.113.1',
    'Browser/5.0 (X12; ComputerOS 64; rv:1024.0)',
    FALSE
  ),
  (
    '@alice:example.com',
    'master signing key',
    NULL,
    NULL,
    NULL,
    NULL,
    TRUE
  ),
  (
    '@alice:example.com',
    'self_signing signing key',
    NULL,
    NULL,
    NULL,
    NULL,
    TRUE
  );
