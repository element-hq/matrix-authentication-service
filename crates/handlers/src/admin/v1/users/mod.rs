// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod add;
mod by_username;
mod deactivate;
mod emails;
mod get;
mod list;
mod lock;
mod set_admin;
mod set_password;
mod unlock;

pub use self::{
    add::{doc as add_doc, handler as add},
    by_username::{doc as by_username_doc, handler as by_username},
    deactivate::{doc as deactivate_doc, handler as deactivate},
    emails::{doc as get_emails_doc, handler as get_emails},
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
    lock::{doc as lock_doc, handler as lock},
    set_admin::{doc as set_admin_doc, handler as set_admin},
    set_password::{doc as set_password_doc, handler as set_password},
    unlock::{doc as unlock_doc, handler as unlock},
};
