// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use axum_extra::extract::Query;
use mas_axum_utils::{InternalError, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng};
use mas_router::{LoginMethodHint, PostAuthAction, UrlBuilder};
use mas_storage::BoxRepository;
use mas_templates::{AppContext, TemplateContext, Templates};
use serde::Deserialize;

use crate::{
    BoundActivityTracker, PreferredLanguage,
    session::{SessionOrFallback, load_session_or_fallback},
};

#[derive(Deserialize)]
pub struct Params {
    #[serde(default, flatten)]
    action: Option<mas_router::AccountAction>,

    #[serde(rename = "org.matrix.msc4198.login_hint")]
    unstable_login_hint: Option<String>,

    #[serde(rename = "io.element.login_method")]
    login_method: Option<LoginMethodHint>,
}

#[tracing::instrument(name = "handlers.views.app.get", skip_all)]
pub async fn get(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    activity_tracker: BoundActivityTracker,
    State(url_builder): State<UrlBuilder>,
    Query(Params {
        action,
        unstable_login_hint,
        login_method,
    }): Query<Params>,
    mut repo: BoxRepository,
    clock: BoxClock,
    mut rng: BoxRng,
    cookie_jar: CookieJar,
) -> Result<impl IntoResponse, InternalError> {
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        Some(PostAuthAction::manage_account(action.clone())),
        &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };

    // TODO: keep the full path, not just the action
    let Some(session) = maybe_session else {
        let mut url = mas_router::Login::and_then(PostAuthAction::manage_account(action));

        if let Some(login_hint) = unstable_login_hint {
            url = url.with_login_hint(login_hint);
        }

        if let Some(login_method) = login_method {
            url = url.with_login_method(login_method);
        }

        return Ok((cookie_jar, url_builder.redirect(&url)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

/// Like `get`, but allow anonymous access.
/// Used for a subset of the account management paths.
/// Needed for e.g. account recovery.
#[tracing::instrument(name = "handlers.views.app.get_anonymous", skip_all)]
pub async fn get_anonymous(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
) -> Result<impl IntoResponse, InternalError> {
    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok(Html(content).into_response())
}

#[cfg(test)]
mod test {
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_data_model::{Clock, UlidExt};
    use mas_router::{AccountAction, LoginMethodHint, Route};
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
    };
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{
        RequestBuilderExt, ResponseExt, TestState, setup, upstream_oauth_provider_params,
    };

    fn location(response: &hyper::Response<String>) -> &str {
        response
            .headers()
            .get(LOCATION)
            .expect("missing Location header")
            .to_str()
            .unwrap()
    }

    /// Add a provider which forwards `kc_idp_hint` from the downstream
    /// authorization request. `upsert` is used because only it persists
    /// `additional_authorization_parameters`.
    async fn provider_forwarding_kc_idp_hint(state: &TestState) -> Ulid {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let id = Ulid::from_datetime_with_rng(state.clock.now(), &mut rng);
        let provider = repo
            .upstream_oauth_provider()
            .upsert(
                &state.clock,
                id,
                UpstreamOAuthProviderParams {
                    additional_authorization_parameters: vec![(
                        "kc_idp_hint".to_owned(),
                        "{{ params.kc_idp_hint }}".to_owned(),
                    )],
                    ..upstream_oauth_provider_params("upstream.example.com", "Upstream Ltd.")
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        provider.id
    }

    /// The deeplink hands the login-method hint over to the login page, next
    /// to the account-management action.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deeplink_threads_the_login_method_hint(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let provider_id = provider_forwarding_kc_idp_hint(&state).await;

        let request = Request::get(format!(
            "/account/?action=org.matrix.profile\
             &io.element.login_method=upstream-oauth2:{provider_id}"
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(
            LOCATION,
            &mas_router::Login::and_then(mas_router::PostAuthAction::manage_account(Some(
                AccountAction::OrgMatrixProfile,
            )))
            .with_login_method(LoginMethodHint::UpstreamOAuth2(provider_id))
            .path_and_query(),
        );
    }

    /// Following the deeplink through to the upstream provider works, but the
    /// templated `additional_authorization_parameters` render empty: there is
    /// no authorization grant on this path to take the downstream parameters
    /// from.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deeplink_does_not_forward_downstream_parameters(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let provider_id = provider_forwarding_kc_idp_hint(&state).await;

        let request = Request::get(format!(
            "/account/?io.element.login_method=upstream-oauth2:{provider_id}&kc_idp_hint=saml"
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let login = location(&response).to_owned();

        let response = state.request(Request::get(login.as_str()).empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let authorize = location(&response).to_owned();
        assert_eq!(
            authorize,
            mas_router::UpstreamOAuth2Authorize::new(provider_id)
                .and_then(mas_router::PostAuthAction::manage_account(None))
                .path_and_query()
        );

        let response = state
            .request(Request::get(authorize.as_str()).empty())
            .await;
        response.assert_status(StatusCode::TEMPORARY_REDIRECT);
        assert!(
            !location(&response).contains("kc_idp_hint"),
            "location: {}",
            location(&response)
        );
    }
}
