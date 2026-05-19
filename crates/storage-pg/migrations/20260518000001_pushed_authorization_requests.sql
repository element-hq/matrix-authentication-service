-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Track which authorization grants were created via the Pushed Authorization
-- Request (PAR) endpoint (RFC 9126 / MSC4305).
ALTER TABLE oauth2_authorization_grants
  ADD COLUMN created_via_par BOOLEAN NOT NULL DEFAULT FALSE;

-- Whether a client is required to use Pushed Authorization Requests for all
-- authorization flows (per RFC 9126 / MSC4305 client metadata).
ALTER TABLE oauth2_clients
  ADD COLUMN require_pushed_authorization_requests BOOLEAN NOT NULL DEFAULT FALSE;
