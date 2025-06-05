// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod add;
mod get;
mod list;
mod revoke;
mod unrevoke;

pub use self::{
    add::{doc as add_doc, handler as add},
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
    revoke::{doc as revoke_doc, handler as revoke},
    unrevoke::{doc as unrevoke_doc, handler as unrevoke},
};
