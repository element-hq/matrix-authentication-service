// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::sync::Arc;

use minijinja::{
    Value,
    value::{Enumerator, Object},
};

/// Site features information.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiteFeatures {
    /// Whether local password-based registration is enabled.
    pub password_registration: bool,

    /// Whether local password-based login is enabled.
    pub password_login: bool,

    /// Whether email-based account recovery is enabled.
    pub account_recovery: bool,

    /// Whether users can log in with their email address.
    pub login_with_email_allowed: bool,
}

impl Object for SiteFeatures {
    fn get_value(self: &Arc<Self>, field: &Value) -> Option<Value> {
        match field.as_str()? {
            "password_registration" => Some(Value::from(self.password_registration)),
            "password_login" => Some(Value::from(self.password_login)),
            "account_recovery" => Some(Value::from(self.account_recovery)),
            "login_with_email_allowed" => Some(Value::from(self.login_with_email_allowed)),
            _ => None,
        }
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&[
            "password_registration",
            "password_login",
            "account_recovery",
            "login_with_email_allowed",
        ])
    }
}
