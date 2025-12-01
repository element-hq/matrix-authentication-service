-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY
  upstream_oauth_links_provider_fk
  ON upstream_oauth_links (upstream_oauth_provider_id);
