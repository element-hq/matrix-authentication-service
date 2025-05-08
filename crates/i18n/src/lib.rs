// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

pub mod sprintf;
pub mod translations;
mod translator;

pub use icu_calendar;
pub use icu_datetime;
pub use icu_locale::{locale, ParseError};
pub use icu_provider::{DataError, DataLocale};

pub use self::{
    sprintf::{Argument, ArgumentList, Message},
    translator::{LoadError, Translator},
};
