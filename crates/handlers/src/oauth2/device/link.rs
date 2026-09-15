// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::LazyLock;

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
    DeviceLinkContext, DeviceLinkFormField, FieldError, FormError, FormState, TemplateContext,
    Templates,
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use serde::{Deserialize, Serialize};

use crate::{Limiter, METER, PreferredLanguage, RequesterFingerprint, SiteConfig};

static USER_CODE_ATTEMPT_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.oauth2.device_code_link_attempt")
        .with_description("Number of user codes submitted on the device link page")
        .with_unit("{attempt}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

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
    State(limiter): State<Limiter>,
    requester: RequesterFingerprint,
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
        &limiter,
        requester,
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
    State(limiter): State<Limiter>,
    requester: RequesterFingerprint,
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
        &limiter,
        requester,
        cookie_jar,
        form,
    )
    .await
}

#[expect(clippy::too_many_arguments)]
async fn handle_code(
    rng: &mut BoxRng,
    clock: &BoxClock,
    mut repo: BoxRepository,
    locale: &DataLocale,
    templates: &Templates,
    url_builder: &UrlBuilder,
    limiter: &Limiter,
    requester: RequesterFingerprint,
    cookie_jar: CookieJar,
    params: Params,
) -> Result<Response, InternalError> {
    let mut form_state = FormState::from_form(&params);

    // If we have a code, find it in the database
    if let Some(code) = &params.code {
        // Rate-limit how many user codes a single requester can try, to make
        // brute-forcing the user code impractical. RFC 8628 section 5.1.
        // This is checked before looking the code up, so that guesses beyond the
        // allowance are never evaluated.
        if let Err(e) = limiter.check_device_code_link(requester) {
            tracing::warn!(error = &e as &dyn std::error::Error, "ratelimit exceeded");
            USER_CODE_ATTEMPT_COUNTER.add(1, &[KeyValue::new(RESULT, "rate_limited")]);

            let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
            let ctx = DeviceLinkContext::new()
                .with_form_state(form_state.with_error_on_form(FormError::RateLimitExceeded))
                .with_csrf(csrf_token.form_value())
                .with_language(*locale);

            let content = templates.render_device_link(&ctx)?;

            return Ok((cookie_jar, Html(content)).into_response());
        }

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
            USER_CODE_ATTEMPT_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);
            let destination = url_builder.redirect(&mas_router::DeviceCodeConsent::new(grant.id));

            return Ok((cookie_jar, destination).into_response());
        }

        // The code isn't valid, set an error on the form
        USER_CODE_ATTEMPT_COUNTER.add(1, &[KeyValue::new(RESULT, "invalid")]);
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hyper::{Request, StatusCode, header::CONTENT_TYPE};
    use mas_router::{Route, SimpleRoute};
    use oauth2_types::{
        registration::ClientRegistrationResponse, requests::DeviceAuthorizationResponse,
    };
    use sqlx::PgPool;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    const ALICE: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    const BOB: IpAddr = IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1));

    /// Start a device authorization grant and return its user code
    async fn get_user_code(state: &TestState) -> String {
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "token_endpoint_auth_method": "none",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                "response_types": [],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let response: ClientRegistrationResponse = response.json();

        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": response.client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let response: DeviceAuthorizationResponse = response.json();

        response.user_code
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_rate_limit(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Render the link page to get a CSRF token. This shouldn't consume any of the
        // rate limit allowance, as no code is submitted
        let request = Request::get(
            mas_router::DeviceCodeLink::default()
                .path_and_query()
                .as_ref(),
        )
        .client_ip(ALICE)
        .empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned();

        let request = Request::post(mas_router::DeviceCodeLink::route())
            .client_ip(ALICE)
            .form(serde_json::json!({
                "csrf": csrf_token,
                "code": "AAAAAA",
            }));
        let request = cookies.with_cookies(request);

        // The default burst allowance is 10 attempts, which should all be told that the
        // code is invalid
        for _ in 0..10 {
            let response = state.request(request.clone()).await;
            response.assert_status(StatusCode::OK);
            let body = response.body();
            assert!(body.contains(r#"data-error-kind="invalid""#));
            assert!(!body.contains("too many requests"));
        }

        // The next attempt should be rate-limited
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(!body.contains(r#"data-error-kind="invalid""#));
        assert!(body.contains("too many requests"));

        // A valid code is refused too: the allowance is checked before the code is
        // looked up, so that guesses beyond it are never evaluated
        let user_code = get_user_code(&state).await;
        let request = Request::get(
            mas_router::DeviceCodeLink::with_code(user_code.clone())
                .path_and_query()
                .as_ref(),
        )
        .client_ip(ALICE)
        .empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("too many requests"));

        // Another requester is unaffected and can still use that code
        let request = Request::get(
            mas_router::DeviceCodeLink::with_code(user_code)
                .path_and_query()
                .as_ref(),
        )
        .client_ip(BOB)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_valid_code(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let user_code = get_user_code(&state).await;

        // A valid code redirects to the consent page
        let request = Request::get(
            mas_router::DeviceCodeLink::with_code(user_code)
                .path_and_query()
                .as_ref(),
        )
        .client_ip(ALICE)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
    }
}
