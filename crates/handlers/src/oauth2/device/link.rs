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
use mas_data_model::{BoxClock, BoxRng, DeviceCodeGrant, normalize_user_code};
use mas_i18n::DataLocale;
use mas_router::UrlBuilder;
use mas_storage::{BoxRepository, RepositoryError};
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

/// Find a device code grant by its user code, ignoring any grant which is no
/// longer usable.
///
/// The liveness checks belong here rather than at the call site because
/// [`handle_code`] tries more than one candidate code: a grant which is
/// expired or has already been used sits at a real row, and must not stop the
/// caller from trying its next candidate.
async fn find_usable_grant(
    repo: &mut BoxRepository,
    clock: &BoxClock,
    user_code: &str,
) -> Result<Option<DeviceCodeGrant>, RepositoryError> {
    Ok(repo
        .oauth2_device_code_grant()
        .find_by_user_code(user_code)
        .await?
        // XXX: We should have different error messages for already exchanged and expired
        .filter(|grant| grant.is_pending())
        .filter(|grant| grant.expires_at > clock.now()))
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
        // Look the code up as it was typed first, so that codes issued before
        // the Crockford alphabet was adopted — which may contain a literal
        // `I`, `L` or `O` — still resolve. Only then apply the decode mapping,
        // which repairs a user who read a `0` as an `O` or a `1` as an `I`.
        //
        // Doing it in this order means the fallback for codes issued by an
        // older version and the repair of a misread code are the same
        // mechanism, so there is no transitional code to remove later.
        let uppercased = code.to_uppercase();
        let normalized = normalize_user_code(code);

        // Note that each candidate is checked for usability as part of its own
        // lookup. A grant which is expired or already used still occupies a
        // row, so testing liveness only after picking a candidate would let a
        // dead grant sitting at the code as typed swallow the lookup and block
        // the fallback below.
        let mut grant = find_usable_grant(&mut repo, clock, &uppercased).await?;

        if grant.is_none() && normalized != uppercased {
            grant = find_usable_grant(&mut repo, clock, &normalized).await?;
        }

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

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_data_model::Client;
    use mas_router::{Route, SimpleRoute};
    use mas_storage::oauth2::OAuth2DeviceCodeGrantParams;
    use oauth2_types::{registration::ClientRegistrationResponse, scope::OPENID};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    /// Register a client which is allowed to use the device code grant.
    async fn device_client(state: &TestState) -> Client {
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

        let mut repo = state.repository().await.unwrap();
        let client = repo
            .oauth2_client()
            .find_by_client_id(&response.client_id)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();
        client
    }

    /// Create a pending device code grant with an exact `user_code`, so that
    /// tests can control the format of the code rather than taking whatever
    /// the generator produces.
    async fn grant_with_user_code(state: &TestState, client: &Client, user_code: &str) {
        grant_with_user_code_expiring_in(
            state,
            client,
            user_code,
            Duration::try_minutes(20).unwrap(),
        )
        .await;
    }

    /// As [`grant_with_user_code`], but with an explicit lifetime. A negative
    /// `expires_in` gives a grant which is already expired, since the store
    /// records `expires_at` as `now + expires_in`.
    async fn grant_with_user_code_expiring_in(
        state: &TestState,
        client: &Client,
        user_code: &str,
        expires_in: Duration,
    ) {
        let mut repo = state.repository().await.unwrap();
        repo.oauth2_device_code_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                OAuth2DeviceCodeGrantParams {
                    client,
                    scope: [OPENID].into_iter().collect(),
                    // `device_code` is unique too, and some of these tests
                    // create more than one grant
                    device_code: format!("devicecode-{user_code}"),
                    user_code: user_code.to_owned(),
                    expires_in,
                    ip_address: None,
                    user_agent: None,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
    }

    /// Submit a code to the link endpoint, returning whether it resolved to a
    /// grant. The `GET` form of the endpoint takes the code as a query
    /// parameter and runs the same lookup as the form `POST`, without needing
    /// a CSRF token.
    async fn submit_code(state: &TestState, code: &str) -> bool {
        let uri = mas_router::DeviceCodeLink::with_code(code.to_owned()).path_and_query();
        let response = state.request(Request::get(&*uri).empty()).await;

        match response.status() {
            StatusCode::SEE_OTHER => {
                let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
                assert!(
                    location.contains("/device/"),
                    "expected a redirect to the consent page, got {location:?}"
                );
                true
            }
            // The form is re-rendered with an error on the field
            StatusCode::OK => {
                assert!(response.body().contains("mfa-code-input"));
                false
            }
            status => panic!("unexpected status {status}"),
        }
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_valid_code(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client = device_client(&state).await;

        grant_with_user_code(&state, &client, "D0WK7B").await;

        assert!(submit_code(&state, "D0WK7B").await);
    }

    /// A user who mistypes the code in the ways the Crockford decode mapping
    /// is defined to repair should still get through.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_applies_the_decode_mapping(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client = device_client(&state).await;

        // Contains both a `0` and a `1`, the two characters with look-alikes
        grant_with_user_code(&state, &client, "D0WK1B").await;

        // Typed verbatim
        assert!(submit_code(&state, "D0WK1B").await);
        // Lowercased
        assert!(submit_code(&state, "d0wk1b").await);
        // `0` read as `O`, and `1` read as `I` or `L`
        assert!(submit_code(&state, "DOWK1B").await);
        assert!(submit_code(&state, "D0WKIB").await);
        assert!(submit_code(&state, "D0WKLB").await);
        assert!(submit_code(&state, "dowklb").await);
    }

    /// The codes we hand out contain no separators, so there is nothing for a
    /// user to optionally include and nothing for the endpoint to strip. This
    /// matches what it did before the Crockford alphabet was adopted.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_does_not_tolerate_separators(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client = device_client(&state).await;

        grant_with_user_code(&state, &client, "D0WK1B").await;

        assert!(!submit_code(&state, "D0W-K1B").await);
        assert!(!submit_code(&state, "D0W K1B").await);
        assert!(!submit_code(&state, " D0WK1B ").await);
    }

    /// User codes issued before the Crockford alphabet was adopted may contain
    /// a literal `I`, `L` or `O`, which the decode mapping would rewrite into
    /// something that no longer matches the stored row. The handler looks the
    /// code up as typed before folding it, which is what keeps those working
    /// across an upgrade.
    ///
    /// This is a regression test for that ordering: it fails if the handler is
    /// ever reduced to a single, folded lookup.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_legacy_code_still_resolves(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client = device_client(&state).await;

        // Every character the decode mapping is lossy over, plus the `U` which
        // is excluded from the alphabet but has no mapping defined for it
        grant_with_user_code(&state, &client, "XIL9OZ").await;
        grant_with_user_code(&state, &client, "QUIRKY").await;

        assert!(submit_code(&state, "XIL9OZ").await);
        assert!(submit_code(&state, "xil9oz").await);
        assert!(submit_code(&state, "QUIRKY").await);
    }

    /// A legacy code and a new-format code which fold onto each other can be
    /// pending at the same time during an upgrade. Each must resolve to its
    /// own grant rather than shadowing the other.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_legacy_and_new_codes_do_not_collide(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client = device_client(&state).await;

        grant_with_user_code(&state, &client, "DOWK7B").await;
        grant_with_user_code(&state, &client, "D0WK7B").await;

        let mut repo = state.repository().await.unwrap();
        let legacy = repo
            .oauth2_device_code_grant()
            .find_by_user_code("DOWK7B")
            .await
            .unwrap()
            .unwrap();
        let current = repo
            .oauth2_device_code_grant()
            .find_by_user_code("D0WK7B")
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();
        assert_ne!(legacy.id, current.id);

        // Each code must reach its own grant: the exact match is tried first,
        // so the fold never steals a lookup from the legacy grant.
        let uri = mas_router::DeviceCodeLink::with_code("DOWK7B".to_owned()).path_and_query();
        let response = state.request(Request::get(&*uri).empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        assert!(location.contains(&legacy.id.to_string()));

        let uri = mas_router::DeviceCodeLink::with_code("D0WK7B".to_owned()).path_and_query();
        let response = state.request(Request::get(&*uri).empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        assert!(location.contains(&current.id.to_string()));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_invalid_code(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client = device_client(&state).await;

        grant_with_user_code(&state, &client, "D0WK7B").await;

        assert!(!submit_code(&state, "ZZZZZZ").await);
        assert!(!submit_code(&state, "").await);
        // Close, but not a code we issued
        assert!(!submit_code(&state, "D0WK7C").await);
    }

    /// A dead grant sitting at the code exactly as typed must not stop the
    /// folded lookup from finding a live one.
    ///
    /// This is the misread case the two-step lookup exists for: the user holds
    /// a live `D0WK1B`, reads the `0` as an `O`, and types `DOWK1B` — which
    /// happens to be an expired grant left over from before the upgrade. If
    /// liveness is only checked after choosing a candidate, that expired row
    /// comes back as `Some`, suppresses the fallback, and is only then
    /// filtered away, so the live grant is never reached.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_expired_grant_does_not_shadow_the_folded_lookup(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client = device_client(&state).await;

        // Already expired, and sits exactly where the typed code lands
        grant_with_user_code_expiring_in(
            &state,
            &client,
            "DOWK1B",
            Duration::try_minutes(-20).unwrap(),
        )
        .await;
        // Live, and is what the user is actually trying to reach
        grant_with_user_code(&state, &client, "D0WK1B").await;

        let mut repo = state.repository().await.unwrap();
        let live = repo
            .oauth2_device_code_grant()
            .find_by_user_code("D0WK1B")
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();

        let uri = mas_router::DeviceCodeLink::with_code("DOWK1B".to_owned()).path_and_query();
        let response = state.request(Request::get(&*uri).empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
        assert!(
            location.contains(&live.id.to_string()),
            "expected the live grant {}, got a redirect to {location:?}",
            live.id
        );
    }

    /// The decode mapping runs one way only: `O` is read as `0`, never the
    /// reverse. So a legacy code containing a literal `O` is reachable by
    /// typing that `O`, but not by typing a `0` in its place.
    ///
    /// This is a limitation rather than a goal — it matches what the endpoint
    /// did before this alphabet was adopted, and only applies to codes issued
    /// by an older version, which expire within 20 minutes of an upgrade. It
    /// is asserted here so the behaviour is documented rather than incidental.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_link_decode_mapping_is_one_directional(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client = device_client(&state).await;

        grant_with_user_code(&state, &client, "DOWK7B").await;

        assert!(submit_code(&state, "DOWK7B").await);
        assert!(!submit_code(&state, "D0WK7B").await);
    }
}
