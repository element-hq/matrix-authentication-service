// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { UUID } from "./index";

/*
+----------------------------+--------------------------+-----------+
| Column                     | Type                     | Modifiers |
|----------------------------+--------------------------+-----------|
| upstream_oauth_provider_id | uuid                     |  not null |
| issuer                     | text                     |  not null |
| scope                      | text                     |  not null |
| client_id                  | text                     |  not null |
| encrypted_client_secret    | text                     |           |
| token_endpoint_signing_alg | text                     |           |
| token_endpoint_auth_method | text                     |  not null |
| created_at                 | timestamp with time zone |  not null |
+----------------------------+--------------------------+-----------+
Indexes:
    "upstream_oauth_providers_pkey" PRIMARY KEY, btree (upstream_oauth_provider_id)
Referenced by:
    TABLE "upstream_oauth_links" CONSTRAINT "upstream_oauth_links_provider_fkey" FOREIGN KEY (upstream_oauth_provider_id) REFERENCES upstream_oauth_providers(upstream_oauth_provider_id)
    TABLE "upstream_oauth_authorization_sessions" CONSTRAINT "upstream_oauth_authorization_sessions_provider_fkey" FOREIGN KEY (upstream_oauth_provider_id) REFERENCES upstream_oauth_providers(upstream_oauth_provider_id)
*/

export interface MUpstreamOauthProvider {
  upstream_oauth_provider_id: UUID<MUpstreamOauthProvider>;
  issuer: string;
  scope: string;
  client_id: string;
  encrypted_client_secret?: string;
  token_endpoint_signing_alg?: string;
  token_endpoint_auth_method: string;
  created_at: Date;
}
