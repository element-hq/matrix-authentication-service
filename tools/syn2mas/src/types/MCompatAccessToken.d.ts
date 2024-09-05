// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { MCompatSession } from "./MCompatSession";

import { UUID } from "./index";

/*
+------------------------+--------------------------+-----------+
| Column                 | Type                     | Modifiers |
|------------------------+--------------------------+-----------|
| compat_access_token_id | uuid                     |  not null |
| compat_session_id      | uuid                     |  not null |
| access_token           | text                     |  not null |
| created_at             | timestamp with time zone |  not null |
| expires_at             | timestamp with time zone |           |
+------------------------+--------------------------+-----------+
Indexes:
    "compat_access_tokens_pkey" PRIMARY KEY, btree (compat_access_token_id)
    "compat_access_tokens_access_token_unique" UNIQUE CONSTRAINT, btree (access_token)
Foreign-key constraints:
    "compat_access_tokens_compat_session_id_fkey" FOREIGN KEY (compat_session_id) REFERENCES compat_sessions(compat_session_id)
Referenced by:
    TABLE "compat_refresh_tokens" CONSTRAINT "compat_refresh_tokens_compat_access_token_id_fkey" FOREIGN KEY (compat_access_token_id) REFERENCES compat_access_tokens(compat_access_toke
n_id)
*/
export interface MCompatAccessToken {
  compat_access_token_id: UUID<MCompatAccessToken>;
  compat_session_id: UUID<MCompatSession>;
  access_token: string;
  created_at: Date;
  expires_at?: Date;
}
