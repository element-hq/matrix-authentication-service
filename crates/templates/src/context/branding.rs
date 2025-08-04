// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

use minijinja::{
    Value,
    value::{Enumerator, Object},
};

/// Site branding information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteBranding {
    server_name: Arc<str>,
    policy_uri: Option<Arc<str>>,
    tos_uri: Option<Arc<str>>,
    imprint: Option<Arc<str>>,
}

impl SiteBranding {
    /// Create a new site branding based on the given server name.
    #[must_use]
    pub fn new(server_name: impl Into<Arc<str>>) -> Self {
        Self {
            server_name: server_name.into(),
            policy_uri: None,
            tos_uri: None,
            imprint: None,
        }
    }

    /// Set the policy URI.
    #[must_use]
    pub fn with_policy_uri(mut self, policy_uri: impl Into<Arc<str>>) -> Self {
        self.policy_uri = Some(policy_uri.into());
        self
    }

    /// Set the terms of service URI.
    #[must_use]
    pub fn with_tos_uri(mut self, tos_uri: impl Into<Arc<str>>) -> Self {
        self.tos_uri = Some(tos_uri.into());
        self
    }

    /// Set the imprint.
    #[must_use]
    pub fn with_imprint(mut self, imprint: impl Into<Arc<str>>) -> Self {
        self.imprint = Some(imprint.into());
        self
    }
}

impl Object for SiteBranding {
    fn get_value(self: &Arc<Self>, name: &Value) -> Option<Value> {
        match name.as_str()? {
            "server_name" => Some(self.server_name.clone().into()),
            "policy_uri" => self.policy_uri.clone().map(Value::from),
            "tos_uri" => self.tos_uri.clone().map(Value::from),
            "imprint" => self.imprint.clone().map(Value::from),
            _ => None,
        }
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&["server_name", "policy_uri", "tos_uri", "imprint"])
    }
}
