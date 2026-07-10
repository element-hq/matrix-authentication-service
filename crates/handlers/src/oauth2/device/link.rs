// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    Form,
    extract::State,
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::Query;
use mas_axum_utils::{
    InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng};
use mas_i18n::DataLocale;
use mas_router::UrlBuilder;
use mas_storage::BoxRepository;
use mas_templates::{
    DeviceLinkContext, DeviceLinkFormField, FieldError, FormState, TemplateContext, Templates,
};
use serde::{Deserialize, Serialize};

use crate::{PreferredLanguage, SiteConfig};

#[derive(Serialize, Deserialize)]
pub struct Params {
    #[serde(default)]
    code: Option<String>,
}

#[tracing::instrument(name = "handlers.oauth2.device.link.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    repo: BoxRepository,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    cookie_jar: CookieJar,
    Query(mut query): Query<Params>,
) -> Result<Response, InternalError> {
    if !site_config.device_code_grant_enabled {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "The Device Authorization Grant is disabled"
        )));
    }
    // When the auto-fill flow is disabled, ignore the `code` query parameter
    // entirely — users must type their user code into the form.
    if !site_config.device_code_user_code_auto_fill_enabled {
        query.code = None;
    }

    handle_code(
        &mut rng,
        &clock,
        repo,
        &locale,
        &templates,
        &url_builder,
        cookie_jar,
        query,
    )
    .await
}

#[tracing::instrument(name = "handlers.oauth2.device.link.post", skip_all)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    repo: BoxRepository,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    cookie_jar: CookieJar,
    Form(form): Form<ProtectedForm<Params>>,
) -> Result<Response, InternalError> {
    if !site_config.device_code_grant_enabled {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "The Device Authorization Grant is disabled"
        )));
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    handle_code(
        &mut rng,
        &clock,
        repo,
        &locale,
        &templates,
        &url_builder,
        cookie_jar,
        form,
    )
    .await
}

async fn handle_code(
    rng: &mut BoxRng,
    clock: &BoxClock,
    mut repo: BoxRepository,
    locale: &DataLocale,
    templates: &Templates,
    url_builder: &UrlBuilder,
    cookie_jar: CookieJar,
    params: Params,
) -> Result<Response, InternalError> {
    let mut form_state = FormState::from_form(&params);

    // If we have a code, find it in the database
    if let Some(code) = &params.code {
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

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);

    // Render the form
    let ctx = DeviceLinkContext::new()
        .with_form_state(form_state)
        .with_csrf(csrf_token.form_value())
        .with_language(*locale);

    let content = templates.render_device_link(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}
