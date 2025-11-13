// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

<<<<<<< HEAD
mod list;

pub use self::list::{doc as list_doc, handler as list};
=======
mod get;
mod list;

pub use self::{
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
};
>>>>>>> v1.6.0
