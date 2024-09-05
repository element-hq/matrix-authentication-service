// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { MUpstreamOauthProvider } from "./MUpstreamOauthProvider";
import { MUser } from "./MUser";

import { UUID } from "./index";

/*
+----------------------------+--------------------------+-----------+
| Column                     | Type                     | Modifiers |
|----------------------------+--------------------------+-----------|
| upstream_oauth_link_id     | uuid                     |  not null |
| upstream_oauth_provider_id | uuid                     |  not null |
| user_id                    | uuid                     |           |
| subject                    | text                     |  not null |
| created_at                 | timestamp with time zone |  not null |
+----------------------------+--------------------------+-----------+
Indexes:
    "upstream_oauth_links_pkey" PRIMARY KEY, btree (upstream_oauth_link_id)
    "upstream_oauth_links_subject_unique" UNIQUE CONSTRAINT, btree (upstream_oauth_provider_id, subject)
Foreign-key constraints:
    "upstream_oauth_link_user_fkey" FOREIGN KEY (user_id) REFERENCES users(user_id)
    "upstream_oauth_links_provider_fkey" FOREIGN KEY (upstream_oauth_provider_id) REFERENCES upstream_oauth_providers(upstream_oauth_provider_id)
Referenced by:
    TABLE "upstream_oauth_authorization_sessions" CONSTRAINT "upstream_oauth_authorization_sessions_link_fkey" FOREIGN KEY (upstream_oauth_link_id) REFERENCES upstream_oauth_links(upstream_oauth_link_id)
*/
export interface MUpstreamOauthLink {
  upstream_oauth_link_id: UUID<MUpstreamOauthLink>;
  upstream_oauth_provider_id: UUID<MUpstreamOauthProvider>;
  user_id?: UUID<MUser>;
  subject: string;
  created_at: Date;
}
