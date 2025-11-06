-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE files in the repository root for full details.
-- Brings in the `users` table from Synapse
CREATE TABLE users (
  name text,
  password_hash text,
  creation_ts bigint,
  admin smallint DEFAULT 0 NOT NULL,
  upgrade_ts bigint,
  is_guest smallint DEFAULT 0 NOT NULL,
  appservice_id text,
  consent_version text,
  consent_server_notice_sent text,
  user_type text,
  deactivated smallint DEFAULT 0 NOT NULL,
  shadow_banned boolean,
  consent_ts bigint,
  approved boolean,
  locked boolean DEFAULT false NOT NULL,
  suspended boolean DEFAULT false NOT NULL
);
