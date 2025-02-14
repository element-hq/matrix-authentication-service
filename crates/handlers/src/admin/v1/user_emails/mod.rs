// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod delete;
mod get;
mod list;

pub use self::{
    delete::{doc as delete_doc, handler as delete},
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
};
