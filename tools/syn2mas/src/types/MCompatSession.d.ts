// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

import { MUser } from "./MUser";

import { UUID } from "./index";

/*
+-------------------+--------------------------+-----------+
| Column            | Type                     | Modifiers |
|-------------------+--------------------------+-----------|
| compat_session_id | uuid                     |  not null |
| user_id           | uuid                     |  not null |
| device_id         | text                     |  not null |
| created_at        | timestamp with time zone |  not null |
| finished_at       | timestamp with time zone |           |
| is_synapse_admin  | boolean                  | not null  |
+-------------------+--------------------------+-----------+
Indexes:
    "compat_sessions_pkey" PRIMARY KEY, btree (compat_session_id)
    "compat_sessions_device_id_unique" UNIQUE CONSTRAINT, btree (device_id)
Foreign-key constraints:
    "compat_sessions_user_id_fkey" FOREIGN KEY (user_id) REFERENCES users(user_id)
Referenced by:
    TABLE "compat_sso_logins" CONSTRAINT "compat_sso_logins_compat_session_id_fkey" FOREIGN KEY (compat_session_id) REFERENCES compat_sessions(compat_session_id) ON DELETE SET NULL
    TABLE "compat_access_tokens" CONSTRAINT "compat_access_tokens_compat_session_id_fkey" FOREIGN KEY (compat_session_id) REFERENCES compat_sessions(compat_session_id)
    TABLE "compat_refresh_tokens" CONSTRAINT "compat_refresh_tokens_compat_session_id_fkey" FOREIGN KEY (compat_session_id) REFERENCES compat_sessions(compat_session_id)
*/

export interface MCompatSession {
  compat_session_id: UUID<MCompatSession>;
  user_id: UUID<MUser>;
  device_id: string;
  created_at: Date;
  finished_at?: Date;
  is_synapse_admin: boolean;
}
