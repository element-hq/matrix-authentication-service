// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

mod get;
mod list;

pub use self::{
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
};
