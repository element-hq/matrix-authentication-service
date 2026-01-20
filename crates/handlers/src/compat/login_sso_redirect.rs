// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{extract::State, response::IntoResponse};
use axum_extra::extract::Query;
use hyper::StatusCode;
use mas_axum_utils::{GenericError, InternalError};
use mas_data_model::{BoxClock, BoxRng};
use mas_router::{CompatLoginSsoAction, CompatLoginSsoComplete, UrlBuilder};
use mas_storage::{BoxRepository, compat::CompatSsoLoginRepository};
use rand::distributions::{Alphanumeric, DistString};
use serde::Deserialize;
use serde_with::serde;
use thiserror::Error;
use url::Url;

use crate::impl_from_error_for_route;

#[derive(Debug, Deserialize)]
pub struct Params {
    #[serde(rename = "redirectUrl")]
    redirect_url: Option<String>,
    action: Option<CompatLoginSsoAction>,

    #[serde(rename = "org.matrix.msc3824.action")]
    unstable_action: Option<CompatLoginSsoAction>,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("Missing redirectUrl")]
    MissingRedirectUrl,

    #[error("invalid redirectUrl")]
    InvalidRedirectUrl,
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(e) => InternalError::new(e).into_response(),
            Self::MissingRedirectUrl | Self::InvalidRedirectUrl => {
                GenericError::new(StatusCode::BAD_REQUEST, self).into_response()
            }
        }
    }
}

#[tracing::instrument(name = "handlers.compat.login_sso_redirect.get", skip_all)]
pub async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    State(url_builder): State<UrlBuilder>,
    Query(params): Query<Params>,
) -> Result<impl IntoResponse, RouteError> {
    // Check the redirectUrl parameter
    let redirect_url = params.redirect_url.ok_or(RouteError::MissingRedirectUrl)?;
    let redirect_url = Url::parse(&redirect_url).map_err(|_| RouteError::InvalidRedirectUrl)?;

    // Do not allow URLs with username or passwords in them
    if !redirect_url.username().is_empty() || redirect_url.password().is_some() {
        return Err(RouteError::InvalidRedirectUrl);
    }

    // On the http/https scheme, verify the URL has a host
    if matches!(redirect_url.scheme(), "http" | "https") && !redirect_url.has_host() {
        return Err(RouteError::InvalidRedirectUrl);
    }

    let token = Alphanumeric.sample_string(&mut rng, 32);
    let login = repo
        .compat_sso_login()
        .add(&mut rng, &clock, token, redirect_url)
        .await?;

    repo.save().await?;

    Ok(url_builder.absolute_redirect(&CompatLoginSsoComplete::new(
        login.id,
        params.action.or(params.unstable_action),
    )))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unstable_action_fallback(pool: PgPool) {
        let state: TestState = TestState::from_pool(pool).await.unwrap();

        let request = Request::get(
            "/_matrix/client/v3/login/sso/redirect?\
             redirectUrl=http://example.com/\
             &org.matrix.msc3824.action=register",
        )
        .empty();

        let response = state.request(request).await;

        response.assert_status(StatusCode::SEE_OTHER);

        let location = response
            .headers()
            .get("Location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("org.matrix.msc3824.action=register"));
        assert!(location.contains("action=register"));
    }
}
