-- Copyright 2024, 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

INSERT INTO user_external_ids
  (
    user_id,
    auth_provider,
    external_id
  )
  VALUES
  (
    '@alice:example.com',
    'oidc-raasu',
    '871.syn30'
  );
