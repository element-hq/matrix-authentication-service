// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

mod add;
mod by_username;
mod deactivate;
mod get;
mod kill_sessions;
mod list;
mod lock;
mod reactivate;
mod set_admin;
mod set_password;
mod unlock;

pub use self::{
    add::{doc as add_doc, handler as add},
    by_username::{doc as by_username_doc, handler as by_username},
    deactivate::{doc as deactivate_doc, handler as deactivate},
    get::{doc as get_doc, handler as get},
    kill_sessions::{doc as kill_sessions_doc, handler as kill_sessions},
    list::{doc as list_doc, handler as list},
    lock::{doc as lock_doc, handler as lock},
    reactivate::{doc as reactivate_doc, handler as reactivate},
    set_admin::{doc as set_admin_doc, handler as set_admin},
    set_password::{doc as set_password_doc, handler as set_password},
    unlock::{doc as unlock_doc, handler as unlock},
};
