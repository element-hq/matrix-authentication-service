// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::transform::TransformOperation;
use axum::{Json, extract::State};
use schemars::JsonSchema;
use serde::Serialize;

use crate::admin::call_context::CallContext;

#[allow(clippy::struct_excessive_bools)]
#[derive(Serialize, JsonSchema)]
pub struct SiteConfig {
    /// The Matrix server name for which this instance is configured
    server_name: String,

    /// Whether password login is enabled.
    pub password_login_enabled: bool,

    /// Whether password registration is enabled.
    pub password_registration_enabled: bool,

<<<<<<< HEAD
=======
    /// Whether a valid email address is required for password registrations.
    pub password_registration_email_required: bool,

>>>>>>> v1.6.0
    /// Whether registration tokens are required for password registrations.
    pub registration_token_required: bool,

    /// Whether users can change their email.
    pub email_change_allowed: bool,

    /// Whether users can change their display name.
    pub displayname_change_allowed: bool,

    /// Whether users can change their password.
    pub password_change_allowed: bool,

    /// Whether users can recover their account via email.
    pub account_recovery_allowed: bool,

    /// Whether users can delete their own account.
    pub account_deactivation_allowed: bool,

    /// Whether CAPTCHA during registration is enabled.
    pub captcha_enabled: bool,

    /// Minimum password complexity, between 0 and 4.
    /// This is a score from zxcvbn.
    #[schemars(range(min = 0, max = 4))]
    pub minimum_password_complexity: u8,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("siteConfig")
        .tag("server")
        .summary("Get informations about the configuration of this MAS instance")
        .response_with::<200, Json<SiteConfig>, _>(|t| {
            t.example(SiteConfig {
                server_name: "example.com".to_owned(),
                password_login_enabled: true,
                password_registration_enabled: true,
<<<<<<< HEAD
=======
                password_registration_email_required: true,
>>>>>>> v1.6.0
                registration_token_required: true,
                email_change_allowed: true,
                displayname_change_allowed: true,
                password_change_allowed: true,
                account_recovery_allowed: true,
                account_deactivation_allowed: true,
                captcha_enabled: true,
                minimum_password_complexity: 3,
            })
        })
}

#[tracing::instrument(name = "handler.admin.v1.site_config", skip_all)]
pub async fn handler(
    _: CallContext,
    State(site_config): State<mas_data_model::SiteConfig>,
) -> Json<SiteConfig> {
    Json(SiteConfig {
        server_name: site_config.server_name,
        password_login_enabled: site_config.password_login_enabled,
        password_registration_enabled: site_config.password_registration_enabled,
<<<<<<< HEAD
=======
        password_registration_email_required: site_config.password_registration_email_required,
>>>>>>> v1.6.0
        registration_token_required: site_config.registration_token_required,
        email_change_allowed: site_config.email_change_allowed,
        displayname_change_allowed: site_config.displayname_change_allowed,
        password_change_allowed: site_config.password_change_allowed,
        account_recovery_allowed: site_config.account_recovery_allowed,
        account_deactivation_allowed: site_config.account_deactivation_allowed,
        captcha_enabled: site_config.captcha.is_some(),
        minimum_password_complexity: site_config.minimum_password_complexity,
    })
}
