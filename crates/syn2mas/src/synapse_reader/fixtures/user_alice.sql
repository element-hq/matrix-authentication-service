-- Copyright 2024, 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

INSERT INTO users
  (
    name,
    password_hash,
    creation_ts,
    admin,
    upgrade_ts,
    is_guest,
    appservice_id,
    consent_version,
    consent_server_notice_sent,
    user_type,
    deactivated,
    shadow_banned,
    consent_ts,
    approved,
    locked,
    suspended
  )
  VALUES
  (
    '@alice:example.com',
    '$2b$12$aaa/aaaaaaaaaa.aaaaaaaaaaaaaaa./aaaaaaaaaaaaaaaaaaa/A',
    1530393962,
    0,
    NULL,
    0,
    NULL,
    '1.0',
    '1.0',
    NULL,
    0,
    NULL,
    NULL,
    NULL,
    false,
    false
  );
