-- Copyright 2024, 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE files in the repository root for full details.

INSERT INTO user_threepids
  (
    user_id,
    medium,
    address,
    validated_at,
    added_at
  )
  VALUES
  (
    '@alice:example.com',
    'email',
    'alice@example.com',
    1554228492026,
    1554228549014
  ),
  (
    '@alice:example.com',
    'msisdn',
    '441189998819991197253',
    1555228492026,
    1555228549014
  );
