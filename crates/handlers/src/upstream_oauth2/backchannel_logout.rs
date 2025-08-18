// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::{HashMap, HashSet};

use axum::{
    Form, Json,
    extract::{Path, State, rejection::FormRejection},
    response::IntoResponse,
};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::{
    BoxClock, BoxRng, UpstreamOAuthProvider, UpstreamOAuthProviderOnBackchannelLogout,
};
use mas_jose::{
    claims::{self, Claim, TimeOptions},
    jwt::JwtDecodeError,
};
use mas_oidc_client::{
    error::JwtVerificationError,
    requests::jose::{JwtVerificationData, verify_signed_jwt},
};
use mas_storage::{
    BoxRepository, Pagination,
    compat::CompatSessionFilter,
    oauth2::OAuth2SessionFilter,
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    upstream_oauth2::UpstreamOAuthSessionFilter,
    user::BrowserSessionFilter,
};
use oauth2_types::errors::{ClientError, ClientErrorCode};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use ulid::Ulid;

use crate::{MetadataCache, impl_from_error_for_route, upstream_oauth2::cache::LazyProviderInfos};

#[derive(Debug, Error)]
pub enum RouteError {
    /// An internal error occurred.
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Invalid request body
    #[error(transparent)]
    InvalidRequestBody(#[from] FormRejection),

    /// Logout token is not a JWT
    #[error("failed to decode logout token")]
    InvalidLogoutToken(#[from] JwtDecodeError),

    /// Logout token failed to be verified
    #[error("failed to verify logout token")]
    LogoutTokenVerification(#[from] JwtVerificationError),

    /// Logout token had invalid claims
    #[error("invalid claims in logout token")]
    InvalidLogoutTokenClaims(#[from] claims::ClaimError),

    /// Logout token has neither a sub nor a sid claim
    #[error("logout token has neither a sub nor a sid claim")]
    NoSubOrSidClaim,

    /// Provider not found
    #[error("provider not found")]
    ProviderNotFound,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(self, Self::Internal(_));

        let response = match self {
            e @ Self::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ClientError::from(ClientErrorCode::ServerError).with_description(e.to_string()),
                ),
            )
                .into_response(),

            e @ (Self::InvalidLogoutToken(_)
            | Self::LogoutTokenVerification(_)
            | Self::InvalidRequestBody(_)
            | Self::InvalidLogoutTokenClaims(_)
            | Self::NoSubOrSidClaim) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidRequest)
                        .with_description(e.to_string()),
                ),
            )
                .into_response(),

            Self::ProviderNotFound => (
                StatusCode::NOT_FOUND,
                Json(
                    ClientError::from(ClientErrorCode::InvalidRequest).with_description(
                        "Upstream OAuth provider not found, is the backchannel logout URI right?"
                            .to_owned(),
                    ),
                ),
            )
                .into_response(),
        };

        (sentry_event_id, response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::JwksError);

#[derive(Deserialize)]
pub(crate) struct BackchannelLogoutRequest {
    logout_token: String,
}

#[derive(Deserialize)]
struct LogoutTokenEvents {
    #[allow(dead_code)] // We just want to check it deserializes
    #[serde(rename = "http://schemas.openid.net/event/backchannel-logout")]
    backchannel_logout: HashMap<String, Value>,
}

const EVENTS: Claim<LogoutTokenEvents> = Claim::new("events");

#[tracing::instrument(
    name = "handlers.upstream_oauth2.backchannel_logout.post",
    fields(upstream_oauth_provider.id = %provider_id),
    skip_all,
)]
pub(crate) async fn post(
    clock: BoxClock,
    mut rng: BoxRng,
    mut repo: BoxRepository,
    State(metadata_cache): State<MetadataCache>,
    State(client): State<reqwest::Client>,
    Path(provider_id): Path<Ulid>,
    request: Result<Form<BackchannelLogoutRequest>, FormRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let Form(request) = request?;
    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    let mut lazy_metadata = LazyProviderInfos::new(&metadata_cache, &provider, &client);

    let jwks =
        mas_oidc_client::requests::jose::fetch_jwks(&client, lazy_metadata.jwks_uri().await?)
            .await?;

    // Validate the logout token. The rules are defined in
    // <https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation>
    //
    // Upon receiving a logout request at the back-channel logout URI, the RP MUST
    // validate the Logout Token as follows:
    //
    //  1. If the Logout Token is encrypted, decrypt it using the keys and
    //     algorithms that the Client specified during Registration that the OP was
    //     to use to encrypt ID Tokens. If ID Token encryption was negotiated with
    //     the OP at Registration time and the Logout Token is not encrypted, the RP
    //     SHOULD reject it.
    //  2. Validate the Logout Token signature in the same way that an ID Token
    //     signature is validated, with the following refinements.
    //  3. Validate the alg (algorithm) Header Parameter in the same way it is
    //     validated for ID Tokens. Like ID Tokens, selection of the algorithm used
    //     is governed by the id_token_signing_alg_values_supported Discovery
    //     parameter and the id_token_signed_response_alg Registration parameter
    //     when they are used; otherwise, the value SHOULD be the default of RS256.
    //     Additionally, an alg with the value none MUST NOT be used for Logout
    //     Tokens.
    //  4. Validate the iss, aud, iat, and exp Claims in the same way they are
    //     validated in ID Tokens.
    //  5. Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
    //  6. Verify that the Logout Token contains an events Claim whose value is JSON
    //     object containing the member name http://schemas.openid.net/event/backchannel-logout.
    //  7. Verify that the Logout Token does not contain a nonce Claim.
    //  8. Optionally verify that another Logout Token with the same jti value has
    //     not been recently received.
    //  9. Optionally verify that the iss Logout Token Claim matches the iss Claim
    //     in an ID Token issued for the current session or a recent session of this
    //     RP with the OP.
    //  10. Optionally verify that any sub Logout Token Claim matches the sub Claim
    //      in an ID Token issued for the current session or a recent session of
    //      this RP with the OP.
    //  11. Optionally verify that any sid Logout Token Claim matches the sid Claim
    //      in an ID Token issued for the current session or a recent session of
    //      this RP with the OP.
    //
    //  If any of the validation steps fails, reject the Logout Token and return an
    // HTTP 400 Bad Request error. Otherwise, proceed to perform the logout actions.
    //
    // The ISS and AUD claims are already checked by the verify_signed_jwt()
    // function.

    // This verifies (1), (2), (3) and the iss and aud claims for (4)
    let token = verify_signed_jwt(
        &request.logout_token,
        JwtVerificationData {
            issuer: provider.issuer.as_deref(),
            jwks: &jwks,
            client_id: &provider.client_id,
            signing_algorithm: &provider.id_token_signed_response_alg,
        },
    )?;

    let (_header, mut claims) = token.into_parts();

    let time_options = TimeOptions::new(clock.now());
    claims::EXP.extract_required_with_options(&mut claims, &time_options)?; // (4)
    claims::IAT.extract_required_with_options(&mut claims, &time_options)?; // (4)

    let sub = claims::SUB.extract_optional(&mut claims)?; // (5)
    let sid = claims::SID.extract_optional(&mut claims)?; // (5)
    if sub.is_none() && sid.is_none() {
        return Err(RouteError::NoSubOrSidClaim);
    }

    EVENTS.extract_required(&mut claims)?; // (6)
    claims::NONCE.assert_absent(&claims)?; // (7)

    // Find the corresponding upstream OAuth 2.0 sessions
    let mut auth_session_filter = UpstreamOAuthSessionFilter::new().for_provider(&provider);
    if let Some(sub) = &sub {
        auth_session_filter = auth_session_filter.with_sub_claim(sub);
    }
    if let Some(sid) = &sid {
        auth_session_filter = auth_session_filter.with_sid_claim(sid);
    }
    let count = repo
        .upstream_oauth_session()
        .count(auth_session_filter)
        .await?;

    tracing::info!(sub, sid, %provider.id, "Backchannel logout received, found {count} corresponding authentication sessions");

    match provider.on_backchannel_logout {
        UpstreamOAuthProviderOnBackchannelLogout::DoNothing => {
            tracing::warn!(%provider.id, "Provider configured to do nothing on backchannel logout");
        }
        UpstreamOAuthProviderOnBackchannelLogout::LogoutBrowserOnly => {
            let filter = BrowserSessionFilter::new()
                .authenticated_by_upstream_sessions_only(auth_session_filter)
                .active_only();
            let affected = repo.browser_session().finish_bulk(&clock, filter).await?;
            tracing::info!("Finished {affected} browser sessions");
        }
        UpstreamOAuthProviderOnBackchannelLogout::LogoutAll => {
            let browser_session_filter = BrowserSessionFilter::new()
                .authenticated_by_upstream_sessions_only(auth_session_filter);

            // We need to loop through all the browser sessions to find all the
            // users affected so that we can trigger a device sync job for them
            let mut cursor = Pagination::first(1000);
            let mut user_ids = HashSet::new();
            loop {
                let browser_sessions = repo
                    .browser_session()
                    .list(browser_session_filter, cursor)
                    .await?;
                for browser_session in browser_sessions.edges {
                    user_ids.insert(browser_session.user.id);
                    cursor = cursor.after(browser_session.id);
                }

                if !browser_sessions.has_next_page {
                    break;
                }
            }

            let browser_sessions_affected = repo
                .browser_session()
                .finish_bulk(&clock, browser_session_filter.active_only())
                .await?;

            let oauth2_session_filter = OAuth2SessionFilter::new()
                .active_only()
                .for_browser_sessions(browser_session_filter);

            let oauth2_sessions_affected = repo
                .oauth2_session()
                .finish_bulk(&clock, oauth2_session_filter)
                .await?;

            let compat_session_filter = CompatSessionFilter::new()
                .active_only()
                .for_browser_sessions(browser_session_filter);

            let compat_sessions_affected = repo
                .compat_session()
                .finish_bulk(&clock, compat_session_filter)
                .await?;

            tracing::info!(
                "Finished {browser_sessions_affected} browser sessions, {oauth2_sessions_affected} OAuth 2.0 sessions and {compat_sessions_affected} compatibility sessions"
            );

            for user_id in user_ids {
                tracing::info!(user.id = %user_id, "Queueing a device sync job for user");
                let job = SyncDevicesJob::new_for_id(user_id);
                repo.queue_job().schedule_job(&mut rng, &clock, job).await?;
            }
        }
    }

    repo.save().await?;

    Ok(())
}
