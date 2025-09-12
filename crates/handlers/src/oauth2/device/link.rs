// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
};
use mas_axum_utils::{InternalError, cookies::CookieJar};
use mas_data_model::BoxClock;
use mas_router::UrlBuilder;
use mas_storage::BoxRepository;
use mas_templates::{
    DeviceLinkContext, DeviceLinkFormField, FieldError, FormState, TemplateContext, Templates,
};
use serde::{Deserialize, Serialize};

use crate::PreferredLanguage;

#[derive(Serialize, Deserialize)]
pub struct Params {
    #[serde(default)]
    code: Option<String>,
}

#[tracing::instrument(name = "handlers.oauth2.device.link.get", skip_all)]
pub(crate) async fn get(
    clock: BoxClock,
    mut repo: BoxRepository,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    cookie_jar: CookieJar,
    Query(query): Query<Params>,
) -> Result<impl IntoResponse, InternalError> {
    let mut form_state = FormState::from_form(&query);

    // If we have a code in query, find it in the database
    if let Some(code) = &query.code {
        // Find the code in the database
        let code = code.to_uppercase();
        let grant = repo
            .oauth2_device_code_grant()
            .find_by_user_code(&code)
            .await?
            // XXX: We should have different error messages for already exchanged and expired
            .filter(|grant| grant.is_pending())
            .filter(|grant| grant.expires_at > clock.now());

        if let Some(grant) = grant {
            // This is a valid code, redirect to the consent page
            // This will in turn redirect to the login page if the user is not logged in
            let destination = url_builder.redirect(&mas_router::DeviceCodeConsent::new(grant.id));

            return Ok((cookie_jar, destination).into_response());
        }

        // The code isn't valid, set an error on the form
        form_state = form_state.with_error_on_field(DeviceLinkFormField::Code, FieldError::Invalid);
    }

    // Rendre the form
    let ctx = DeviceLinkContext::new()
        .with_form_state(form_state)
        .with_language(locale);

    let content = templates.render_device_link(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}
