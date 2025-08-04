// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Requests for the [Authorization Code flow].
//!
//! [Authorization Code flow]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth

use std::{collections::HashSet, num::NonZeroU32};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use language_tags::LanguageTag;
use mas_iana::oauth::{OAuthAuthorizationEndpointResponseType, PkceCodeChallengeMethod};
use mas_jose::claims::{self, TokenHash};
use oauth2_types::{
    pkce,
    prelude::CodeChallengeMethodExt,
    requests::{
        AccessTokenRequest, AccessTokenResponse, AuthorizationCodeGrant, AuthorizationRequest,
        Display, Prompt, ResponseMode,
    },
    scope::{OPENID, Scope},
};
use rand::{
    Rng,
    distributions::{Alphanumeric, DistString},
};
use serde::Serialize;
use url::Url;

use super::jose::JwtVerificationData;
use crate::{
    error::{AuthorizationError, IdTokenError, TokenAuthorizationCodeError},
    requests::{jose::verify_id_token, token::request_access_token},
    types::{IdToken, client_credentials::ClientCredentials},
};

/// The data necessary to build an authorization request.
#[derive(Debug, Clone)]
pub struct AuthorizationRequestData {
    /// The ID obtained when registering the client.
    pub client_id: String,

    /// The scope to authorize.
    ///
    /// If the OpenID Connect scope token (`openid`) is not included, it will be
    /// added.
    pub scope: Scope,

    /// The URI to redirect the end-user to after the authorization.
    ///
    /// It must be one of the redirect URIs provided during registration.
    pub redirect_uri: Url,

    /// The PKCE methods supported by the issuer.
    ///
    /// This field should be cloned from the provider metadata. If it is not
    /// set, this security measure will not be used.
    pub code_challenge_methods_supported: Option<Vec<PkceCodeChallengeMethod>>,

    /// How the Authorization Server should display the authentication and
    /// consent user interface pages to the End-User.
    pub display: Option<Display>,

    /// Whether the Authorization Server should prompt the End-User for
    /// reauthentication and consent.
    ///
    /// If [`Prompt::None`] is used, it must be the only value.
    pub prompt: Option<Vec<Prompt>>,

    /// The allowable elapsed time in seconds since the last time the End-User
    /// was actively authenticated by the OpenID Provider.
    pub max_age: Option<NonZeroU32>,

    /// End-User's preferred languages and scripts for the user interface.
    pub ui_locales: Option<Vec<LanguageTag>>,

    /// ID Token previously issued by the Authorization Server being passed as a
    /// hint about the End-User's current or past authenticated session with the
    /// Client.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the login identifier the End-User
    /// might use to log in.
    pub login_hint: Option<String>,

    /// Requested Authentication Context Class Reference values.
    pub acr_values: Option<HashSet<String>>,

    /// Requested response mode.
    pub response_mode: Option<ResponseMode>,
}

impl AuthorizationRequestData {
    /// Constructs a new `AuthorizationRequestData` with all the required
    /// fields.
    #[must_use]
    pub fn new(client_id: String, scope: Scope, redirect_uri: Url) -> Self {
        Self {
            client_id,
            scope,
            redirect_uri,
            code_challenge_methods_supported: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            response_mode: None,
        }
    }

    /// Set the `code_challenge_methods_supported` field of this
    /// `AuthorizationRequestData`.
    #[must_use]
    pub fn with_code_challenge_methods_supported(
        mut self,
        code_challenge_methods_supported: Vec<PkceCodeChallengeMethod>,
    ) -> Self {
        self.code_challenge_methods_supported = Some(code_challenge_methods_supported);
        self
    }

    /// Set the `display` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_display(mut self, display: Display) -> Self {
        self.display = Some(display);
        self
    }

    /// Set the `prompt` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_prompt(mut self, prompt: Vec<Prompt>) -> Self {
        self.prompt = Some(prompt);
        self
    }

    /// Set the `max_age` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_max_age(mut self, max_age: NonZeroU32) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Set the `ui_locales` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_ui_locales(mut self, ui_locales: Vec<LanguageTag>) -> Self {
        self.ui_locales = Some(ui_locales);
        self
    }

    /// Set the `id_token_hint` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_id_token_hint(mut self, id_token_hint: String) -> Self {
        self.id_token_hint = Some(id_token_hint);
        self
    }

    /// Set the `login_hint` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_login_hint(mut self, login_hint: String) -> Self {
        self.login_hint = Some(login_hint);
        self
    }

    /// Set the `acr_values` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_acr_values(mut self, acr_values: HashSet<String>) -> Self {
        self.acr_values = Some(acr_values);
        self
    }

    /// Set the `response_mode` field of this `AuthorizationRequestData`.
    #[must_use]
    pub fn with_response_mode(mut self, response_mode: ResponseMode) -> Self {
        self.response_mode = Some(response_mode);
        self
    }
}

/// The data necessary to validate a response from the Token endpoint in the
/// Authorization Code flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationValidationData {
    /// A unique identifier for the request.
    pub state: String,

    /// A string to mitigate replay attacks.
    /// Used when the `openid` scope is set (and therefore we are using OpenID
    /// Connect).
    pub nonce: Option<String>,

    /// The URI where the end-user will be redirected after authorization.
    pub redirect_uri: Url,

    /// A string to correlate the authorization request to the token request.
    pub code_challenge_verifier: Option<String>,
}

#[derive(Clone, Serialize)]
struct FullAuthorizationRequest {
    #[serde(flatten)]
    inner: AuthorizationRequest,

    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pkce: Option<pkce::AuthorizationRequest>,
}

/// Build the authorization request.
fn build_authorization_request(
    authorization_data: AuthorizationRequestData,
    rng: &mut impl Rng,
) -> Result<(FullAuthorizationRequest, AuthorizationValidationData), AuthorizationError> {
    let AuthorizationRequestData {
        client_id,
        scope,
        redirect_uri,
        code_challenge_methods_supported,
        display,
        prompt,
        max_age,
        ui_locales,
        id_token_hint,
        login_hint,
        acr_values,
        response_mode,
    } = authorization_data;

    let is_openid = scope.contains(&OPENID);

    // Generate a random CSRF "state" token and a nonce.
    let state = Alphanumeric.sample_string(rng, 16);

    // Generate a random nonce if we're in 'OpenID Connect' mode
    let nonce = is_openid.then(|| Alphanumeric.sample_string(rng, 16));

    // Use PKCE, whenever possible.
    let (pkce, code_challenge_verifier) = if code_challenge_methods_supported
        .iter()
        .any(|methods| methods.contains(&PkceCodeChallengeMethod::S256))
    {
        let mut verifier = [0u8; 32];
        rng.fill(&mut verifier);

        let method = PkceCodeChallengeMethod::S256;
        let verifier = Base64UrlUnpadded::encode_string(&verifier);
        let code_challenge = method.compute_challenge(&verifier)?.into();

        let pkce = pkce::AuthorizationRequest {
            code_challenge_method: method,
            code_challenge,
        };

        (Some(pkce), Some(verifier))
    } else {
        (None, None)
    };

    let auth_request = FullAuthorizationRequest {
        inner: AuthorizationRequest {
            response_type: OAuthAuthorizationEndpointResponseType::Code.into(),
            client_id,
            redirect_uri: Some(redirect_uri.clone()),
            scope,
            state: Some(state.clone()),
            response_mode,
            nonce: nonce.clone(),
            display,
            prompt,
            max_age,
            ui_locales,
            id_token_hint,
            login_hint,
            acr_values,
            request: None,
            request_uri: None,
            registration: None,
        },
        pkce,
    };

    let auth_data = AuthorizationValidationData {
        state,
        nonce,
        redirect_uri,
        code_challenge_verifier,
    };

    Ok((auth_request, auth_data))
}

/// Build the URL for authenticating at the Authorization endpoint.
///
/// # Arguments
///
/// * `authorization_endpoint` - The URL of the issuer's authorization endpoint.
///
/// * `authorization_data` - The data necessary to build the authorization
///   request.
///
/// * `rng` - A random number generator.
///
/// # Returns
///
/// A URL to be opened in a web browser where the end-user will be able to
/// authorize the given scope, and the [`AuthorizationValidationData`] to
/// validate this request.
///
/// The redirect URI will receive parameters in its query:
///
/// * A successful response will receive a `code` and a `state`.
///
/// * If the authorization fails, it should receive an `error` parameter with a
///   [`ClientErrorCode`] and optionally an `error_description`.
///
/// # Errors
///
/// Returns an error if preparing the URL fails.
///
/// [`VerifiedClientMetadata`]: oauth2_types::registration::VerifiedClientMetadata
/// [`ClientErrorCode`]: oauth2_types::errors::ClientErrorCode
pub fn build_authorization_url(
    authorization_endpoint: Url,
    authorization_data: AuthorizationRequestData,
    rng: &mut impl Rng,
) -> Result<(Url, AuthorizationValidationData), AuthorizationError> {
    tracing::debug!(
        scope = ?authorization_data.scope,
        "Authorizing..."
    );

    let (authorization_request, validation_data) =
        build_authorization_request(authorization_data, rng)?;

    let authorization_query = serde_urlencoded::to_string(authorization_request)?;

    let mut authorization_url = authorization_endpoint;

    // Add our parameters to the query, because the URL might already have one.
    let mut full_query = authorization_url
        .query()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    if !full_query.is_empty() {
        full_query.push('&');
    }
    full_query.push_str(&authorization_query);

    authorization_url.set_query(Some(&full_query));

    Ok((authorization_url, validation_data))
}

/// Exchange an authorization code for an access token.
///
/// This should be used as the first step for logging in, and to request a
/// token with a new scope.
///
/// # Arguments
///
/// * `http_client` - The reqwest client to use for making HTTP requests.
///
/// * `client_credentials` - The credentials obtained when registering the
///   client.
///
/// * `token_endpoint` - The URL of the issuer's Token endpoint.
///
/// * `code` - The authorization code returned at the Authorization endpoint.
///
/// * `validation_data` - The validation data that was returned when building
///   the Authorization URL, for the state returned at the Authorization
///   endpoint.
///
/// * `id_token_verification_data` - The data required to verify the ID Token in
///   the response.
///
///   The signing algorithm corresponds to the `id_token_signed_response_alg`
///   field in the client metadata.
///
///   If it is not provided, the ID Token won't be verified. Note that in the
///   OpenID Connect specification, this verification is required.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails, the response is invalid or the
/// verification of the ID Token fails.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(token_endpoint))]
pub async fn access_token_with_authorization_code(
    http_client: &reqwest::Client,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    code: String,
    validation_data: AuthorizationValidationData,
    id_token_verification_data: Option<JwtVerificationData<'_>>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<(AccessTokenResponse, Option<IdToken<'static>>), TokenAuthorizationCodeError> {
    tracing::debug!("Exchanging authorization code for access token...");

    let token_response = request_access_token(
        http_client,
        client_credentials,
        token_endpoint,
        AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
            code: code.clone(),
            redirect_uri: Some(validation_data.redirect_uri),
            code_verifier: validation_data.code_challenge_verifier,
        }),
        now,
        rng,
    )
    .await?;

    let id_token = if let Some(verification_data) = id_token_verification_data {
        let signing_alg = verification_data.signing_algorithm;

        let id_token = token_response
            .id_token
            .as_deref()
            .ok_or(IdTokenError::MissingIdToken)?;

        let id_token = verify_id_token(id_token, verification_data, None, now)?;

        let mut claims = id_token.payload().clone();

        // Access token hash must match.
        claims::AT_HASH
            .extract_optional_with_options(
                &mut claims,
                TokenHash::new(signing_alg, &token_response.access_token),
            )
            .map_err(IdTokenError::from)?;

        // Code hash must match.
        claims::C_HASH
            .extract_optional_with_options(&mut claims, TokenHash::new(signing_alg, &code))
            .map_err(IdTokenError::from)?;

        // Nonce must match if we have one.
        if let Some(nonce) = validation_data.nonce.as_deref() {
            claims::NONCE
                .extract_required_with_options(&mut claims, nonce)
                .map_err(IdTokenError::from)?;
        }

        Some(id_token.into_owned())
    } else {
        None
    };

    Ok((token_response, id_token))
}
