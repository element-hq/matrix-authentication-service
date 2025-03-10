// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod get;
mod get_latest;
mod set;

pub use self::{
    get::{doc as get_doc, handler as get},
    get_latest::{doc as get_latest_doc, handler as get_latest},
    set::{doc as set_doc, handler as set},
};
