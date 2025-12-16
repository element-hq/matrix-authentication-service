// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::Query;
use hyper::StatusCode;
use mas_axum_utils::{SessionInfoExt, cookies::CookieJar, record_error};
use mas_data_model::{BoxClock, BoxRng};
use mas_keystore::Keystore;
use mas_oidc_client::requests::jose::{JwtVerificationData, verify_signed_jwt};
use mas_router::UrlBuilder;
use mas_storage::{
    BoxRepository, RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::BrowserSessionRepository,
};
use oauth2_types::errors::{ClientError, ClientErrorCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::{BoundActivityTracker, impl_from_error_for_route};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct EndSessionParam {
    id_token_hint: String,
    post_logout_redirect_uri: String,
}

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> Response {
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let response = match self {
            Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            )
                .into_response(),
        };

        (sentry_event_id, response).into_response()
    }
}

#[tracing::instrument(name = "handlers.oauth2.end_session.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(key_store): State<Keystore>,
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(params): Query<EndSessionParam>,
    cookie_jar: CookieJar,
) -> Result<Response, RouteError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let Some(browser_session_id) = session_info.current_session_id() else {
        info!("Cannot get browser session id from cookie");
        return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
    };

    let Some(browser_session) = repo.browser_session().lookup(browser_session_id).await? else {
        info!(
            "Cannot find browser session[browser session id={}]",
            browser_session_id
        );
        return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
    };

    let Some(oauth_session) = repo
        .oauth2_session()
        .find_by_browser_session(browser_session.id)
        .await?
    else {
        info!(
            "Cannot find oauth2 session[browser session id={}]",
            browser_session_id
        );
        return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
    };

    let Some(client) = repo.oauth2_client().lookup(oauth_session.client_id).await? else {
        info!(
            "Cannot find client [browser session id={}, oauth2 session id: {}]",
            browser_session_id, oauth_session.id
        );
        return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
    };

    if client.id_token_signed_response_alg.is_none() {
        info!(
            "No Signed ID Token Algorithm is present [browser session id={}, oauth2 session id: {}]",
            browser_session_id, oauth_session.id
        );
        return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
    }

    let jwks = key_store.public_jwks();
    let issuer: String = url_builder.oidc_issuer().into();

    let id_token_verification_data = JwtVerificationData {
        issuer: Some(&issuer),
        jwks: &jwks,
        signing_algorithm: &client.id_token_signed_response_alg.unwrap(),
        client_id: &client.client_id,
    };

    if let Err(e) = verify_signed_jwt(&params.id_token_hint, id_token_verification_data) {
        info!(
            "Cannot verify id_token [browser session id={}, oauth2 session id: {}, id_token={}]: {:?}",
            browser_session_id, oauth_session.id, params.id_token_hint, e
        );
        return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
    }

    // Check that the session is still valid.
    if !oauth_session.is_valid() {
        info!(
            "Invalid oauth session [browser session id={}, oauth2 session id: {}]",
            browser_session_id, oauth_session.id
        );
        // If the session is not valid, we redirect to post logout uri
        return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
    }

    activity_tracker
        .record_oauth2_session(&clock, &oauth_session)
        .await;

    // schedule a job which syncs the list of devices of a user with the homeserver
    if let Some(user_id) = oauth_session.user_id {
        let Some(user) = repo.user().lookup(user_id).await? else {
            info!(
                "Cannot find user [browser session id={}, oauth2 session id: {}, user id: {}]",
                browser_session_id, oauth_session.id, user_id
            );
            return Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response());
        };

        repo.queue_job()
            .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
            .await?;
    }

    // Now that we checked everything, we can end the session.
    repo.oauth2_session().finish(&clock, oauth_session).await?;

    activity_tracker
        .record_browser_session(&clock, &browser_session)
        .await;
    repo.browser_session()
        .finish(&clock, browser_session)
        .await?;

    repo.save().await?;

    // We always want to clear out the session cookie, even if the session was
    // invalid
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    Ok((cookie_jar, Redirect::to(&params.post_logout_redirect_uri)).into_response())
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_axum_utils::{SessionInfo, SessionInfoExt};
    use mas_data_model::{Clock as _, Session};
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_jose::jwt::{JsonWebSignatureHeader, Jwt};
    use mas_keystore::Keystore;
    use mas_router::SimpleRoute;
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        scope::{OPENID, Scope},
    };
    use rand_chacha::ChaChaRng;
    use serde::Serialize;
    use serde_json::Value;
    use sqlx::PgPool;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    #[derive(Serialize)]
    struct Query {
        id_token_hint: String,
        post_logout_redirect_uri: String,
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_end_sessions(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "id_token_signed_response_alg": "RS256",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

        // Create a user and its browser session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, Some("Chrome".to_owned()))
            .await
            .unwrap();

        // Lookup the client in the database and add oauth2 session
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();
        let oauth2_session: Session = repo
            .oauth2_session()
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Generate id_token
        let id_token_hint_claims = serde_json::json!({
            "aud": client_id,
            "iss": "https://example.com/",
        });

        let id_token_hint: Jwt<'_, Value> =
            sign_token(&mut rng, &state.key_store, id_token_hint_claims.clone()).unwrap();

        let mut cookie_jar = state.cookie_jar();
        let info = SessionInfo::from_session(&browser_session);
        cookie_jar = cookie_jar.update_session_info(&info);
        let cookies = CookieHelper::new();
        cookies.import(cookie_jar);

        let q = Query {
            id_token_hint: id_token_hint.into_string(),
            post_logout_redirect_uri: "https://example.com/".to_owned(),
        };

        let query = serde_urlencoded::to_string(q).unwrap();
        let url = format!("{}?{}", mas_router::OAuth2EndSession::PATH, query);
        let request = Request::get(url).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // The finished_at timestamp should be the same as the current time
        let mut repo = state.repository().await.unwrap();
        let expected = repo
            .browser_session()
            .lookup(browser_session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(expected.finished_at.unwrap(), state.clock.now());
        let expected_oauth2_session: Session = repo
            .oauth2_session()
            .lookup(oauth2_session.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            expected_oauth2_session.finished_at().unwrap(),
            state.clock.now()
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_end_sessions_with_no_existing_oauth2_session(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "id_token_signed_response_alg": "RS256",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

        // Create a user and its browser session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, Some("Chrome".to_owned()))
            .await
            .unwrap();

        // We do not add any oauth2 session...

        repo.save().await.unwrap();

        // Generate id_token
        let id_token_hint_claims = serde_json::json!({
            "aud": client_id,
            "iss": "https://example.com/",
        });

        let id_token_hint: Jwt<'_, Value> =
            sign_token(&mut rng, &state.key_store, id_token_hint_claims.clone()).unwrap();

        let mut cookie_jar = state.cookie_jar();
        let info = SessionInfo::from_session(&browser_session);
        cookie_jar = cookie_jar.update_session_info(&info);
        let cookies = CookieHelper::new();
        cookies.import(cookie_jar);

        let q = Query {
            id_token_hint: id_token_hint.into_string(),
            post_logout_redirect_uri: "https://example.com/".to_owned(),
        };

        let query = serde_urlencoded::to_string(q).unwrap();
        let url = format!("{}?{}", mas_router::OAuth2EndSession::PATH, query);
        let request = Request::get(url).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_end_sessions_with_client_with_no_response_algorithm(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                // We do not define any response algorithm
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

        // Create a user and its browser session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, Some("Chrome".to_owned()))
            .await
            .unwrap();

        // Lookup the client in the database and add oauth2 session
        repo.oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();

        // Generate id_token
        let id_token_hint_claims = serde_json::json!({
            "aud": client_id,
            "iss": "https://example.com/",
        });

        let id_token_hint: Jwt<'_, Value> =
            sign_token(&mut rng, &state.key_store, id_token_hint_claims.clone()).unwrap();

        let mut cookie_jar = state.cookie_jar();
        let info = SessionInfo::from_session(&browser_session);
        cookie_jar = cookie_jar.update_session_info(&info);
        let cookies = CookieHelper::new();
        cookies.import(cookie_jar);

        let q = Query {
            id_token_hint: id_token_hint.into_string(),
            post_logout_redirect_uri: "https://example.com/".to_owned(),
        };

        let query = serde_urlencoded::to_string(q).unwrap();
        let url = format!("{}?{}", mas_router::OAuth2EndSession::PATH, query);
        let request = Request::get(url).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_end_sessions_with_no_browser_session_in_cookie(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "id_token_signed_response_alg": "RS256",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

        // Generate id_token
        let id_token_hint_claims = serde_json::json!({
            "aud": client_id,
            "iss": "https://example.com/",
        });

        let id_token_hint: Jwt<'_, Value> =
            sign_token(&mut rng, &state.key_store, id_token_hint_claims.clone()).unwrap();

        // We will send the cookie with no session id
        let cookie_jar = state.cookie_jar();
        let cookies = CookieHelper::new();
        cookies.import(cookie_jar);

        let q = Query {
            id_token_hint: id_token_hint.into_string(),
            post_logout_redirect_uri: "https://example.com/".to_owned(),
        };

        let query = serde_urlencoded::to_string(q).unwrap();
        let url = format!("{}?{}", mas_router::OAuth2EndSession::PATH, query);
        let request = Request::get(url).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_end_sessions_with_wrong_issuer_in_id_token(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "id_token_signed_response_alg": "RS256",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

        // Create a user and its browser session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, Some("Chrome".to_owned()))
            .await
            .unwrap();

        // Lookup the client in the database and add oauth2 session
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();
        repo.oauth2_session()
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Generate id token
        let id_token_hint_claims = serde_json::json!({
            "aud": client_id,
            // Set wrong issuer
            "iss": "https://wrongissuer.com/",
        });

        let id_token_hint: Jwt<'_, Value> =
            sign_token(&mut rng, &state.key_store, id_token_hint_claims.clone()).unwrap();

        let mut cookie_jar = state.cookie_jar();
        let info = SessionInfo::from_session(&browser_session);
        cookie_jar = cookie_jar.update_session_info(&info);
        let cookies = CookieHelper::new();
        cookies.import(cookie_jar);

        let q = Query {
            id_token_hint: id_token_hint.into_string(),
            post_logout_redirect_uri: "https://example.com/".to_owned(),
        };

        let query = serde_urlencoded::to_string(q).unwrap();
        let url = format!("{}?{}", mas_router::OAuth2EndSession::PATH, query);
        let request = Request::get(url).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_end_sessions_with_wrong_client_id_in_id_token(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code", "refresh_token"],
                "id_token_signed_response_alg": "RS256",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let ClientRegistrationResponse { client_id, .. } = response.json();

        // Create a user and its browser session
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, Some("Chrome".to_owned()))
            .await
            .unwrap();

        // Lookup the client in the database and add oauth2 session
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();
        repo.oauth2_session()
            .add_from_browser_session(
                &mut state.rng(),
                &state.clock,
                &client,
                &browser_session,
                Scope::from_iter([OPENID]),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Generate id_token
        let id_token_hint_claims = serde_json::json!({
            // Set wrong client id
            "aud": "wrong_client_id",
            "iss": "https://example.com/",
        });

        let id_token_hint: Jwt<'_, Value> =
            sign_token(&mut rng, &state.key_store, id_token_hint_claims.clone()).unwrap();

        let mut cookie_jar = state.cookie_jar();
        let info = SessionInfo::from_session(&browser_session);
        cookie_jar = cookie_jar.update_session_info(&info);
        let cookies = CookieHelper::new();
        cookies.import(cookie_jar);

        let q = Query {
            id_token_hint: id_token_hint.into_string(),
            post_logout_redirect_uri: "https://example.com/".to_owned(),
        };

        let query = serde_urlencoded::to_string(q).unwrap();
        let url = format!("{}?{}", mas_router::OAuth2EndSession::PATH, query);
        let request = Request::get(url).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
    }

    // same util function is defined in link.rs, might be good to define it in
    // test_utils.rs
    pub fn sign_token(
        rng: &mut ChaChaRng,
        keystore: &Keystore,
        payload: Value,
    ) -> Result<Jwt<'static, Value>, mas_jose::jwt::JwtSignatureError> {
        let key = keystore
            .signing_key_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();

        let signer = key
            .params()
            .signing_key_for_alg(&JsonWebSignatureAlg::Rs256)
            .unwrap();

        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);

        Jwt::sign_with_rng(rng, header, payload, &signer)
    }
}
