// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Requests and response types to interact with the [OAuth 2.0] specification.
//!
//! [OAuth 2.0]: https://oauth.net/2/

use std::{collections::HashSet, fmt, hash::Hash, num::NonZeroU32};

use chrono::{DateTime, Duration, Utc};
use language_tags::LanguageTag;
use mas_iana::oauth::{OAuthAccessTokenType, OAuthTokenTypeHint};
use serde::{Deserialize, Serialize};
use serde_with::{
    DeserializeFromStr, DisplayFromStr, DurationSeconds, SerializeDisplay, StringWithSeparator,
    TimestampSeconds, formats::SpaceSeparator, serde_as, skip_serializing_none,
};
use url::Url;

use crate::{response_type::ResponseType, scope::Scope};

// ref: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml

/// The mechanism to be used for returning Authorization Response parameters
/// from the Authorization Endpoint.
///
/// Defined in [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes).
#[derive(
    Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, SerializeDisplay, DeserializeFromStr,
)]
#[non_exhaustive]
pub enum ResponseMode {
    /// Authorization Response parameters are encoded in the query string added
    /// to the `redirect_uri`.
    Query,

    /// Authorization Response parameters are encoded in the fragment added to
    /// the `redirect_uri`.
    Fragment,

    /// Authorization Response parameters are encoded as HTML form values that
    /// are auto-submitted in the User Agent, and thus are transmitted via the
    /// HTTP `POST` method to the Client, with the result parameters being
    /// encoded in the body using the `application/x-www-form-urlencoded`
    /// format.
    ///
    /// Defined in [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).
    FormPost,

    /// An unknown value.
    Unknown(String),
}

impl core::fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResponseMode::Query => f.write_str("query"),
            ResponseMode::Fragment => f.write_str("fragment"),
            ResponseMode::FormPost => f.write_str("form_post"),
            ResponseMode::Unknown(s) => f.write_str(s),
        }
    }
}

impl core::str::FromStr for ResponseMode {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "query" => Ok(ResponseMode::Query),
            "fragment" => Ok(ResponseMode::Fragment),
            "form_post" => Ok(ResponseMode::FormPost),
            s => Ok(ResponseMode::Unknown(s.to_owned())),
        }
    }
}

/// Value that specifies how the Authorization Server displays the
/// authentication and consent user interface pages to the End-User.
///
/// Defined in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
#[derive(
    Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, SerializeDisplay, DeserializeFromStr,
)]
#[non_exhaustive]
pub enum Display {
    /// The Authorization Server should display the authentication and consent
    /// UI consistent with a full User Agent page view.
    ///
    /// This is the default display mode.
    Page,

    /// The Authorization Server should display the authentication and consent
    /// UI consistent with a popup User Agent window.
    Popup,

    /// The Authorization Server should display the authentication and consent
    /// UI consistent with a device that leverages a touch interface.
    Touch,

    /// The Authorization Server should display the authentication and consent
    /// UI consistent with a "feature phone" type display.
    Wap,

    /// An unknown value.
    Unknown(String),
}

impl core::fmt::Display for Display {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Display::Page => f.write_str("page"),
            Display::Popup => f.write_str("popup"),
            Display::Touch => f.write_str("touch"),
            Display::Wap => f.write_str("wap"),
            Display::Unknown(s) => f.write_str(s),
        }
    }
}

impl core::str::FromStr for Display {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "page" => Ok(Display::Page),
            "popup" => Ok(Display::Popup),
            "touch" => Ok(Display::Touch),
            "wap" => Ok(Display::Wap),
            s => Ok(Display::Unknown(s.to_owned())),
        }
    }
}

impl Default for Display {
    fn default() -> Self {
        Self::Page
    }
}

/// Value that specifies whether the Authorization Server prompts the End-User
/// for reauthentication and consent.
///
/// Defined in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest).
#[derive(
    Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, SerializeDisplay, DeserializeFromStr,
)]
#[non_exhaustive]
pub enum Prompt {
    /// The Authorization Server must not display any authentication or consent
    /// user interface pages.
    None,

    /// The Authorization Server should prompt the End-User for
    /// reauthentication.
    Login,

    /// The Authorization Server should prompt the End-User for consent before
    /// returning information to the Client.
    Consent,

    /// The Authorization Server should prompt the End-User to select a user
    /// account.
    ///
    /// This enables an End-User who has multiple accounts at the Authorization
    /// Server to select amongst the multiple accounts that they might have
    /// current sessions for.
    SelectAccount,

    /// The Authorization Server should prompt the End-User to create a user
    /// account.
    ///
    /// Defined in [Initiating User Registration via OpenID Connect](https://openid.net/specs/openid-connect-prompt-create-1_0.html).
    Create,

    /// An unknown value.
    Unknown(String),
}

impl core::fmt::Display for Prompt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Prompt::None => f.write_str("none"),
            Prompt::Login => f.write_str("login"),
            Prompt::Consent => f.write_str("consent"),
            Prompt::SelectAccount => f.write_str("select_account"),
            Prompt::Create => f.write_str("create"),
            Prompt::Unknown(s) => f.write_str(s),
        }
    }
}

impl core::str::FromStr for Prompt {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Prompt::None),
            "login" => Ok(Prompt::Login),
            "consent" => Ok(Prompt::Consent),
            "select_account" => Ok(Prompt::SelectAccount),
            "create" => Ok(Prompt::Create),
            s => Ok(Prompt::Unknown(s.to_owned())),
        }
    }
}

/// The body of a request to the [Authorization Endpoint].
///
/// [Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
#[skip_serializing_none]
#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub struct AuthorizationRequest {
    /// OAuth 2.0 Response Type value that determines the authorization
    /// processing flow to be used.
    pub response_type: ResponseType,

    /// OAuth 2.0 Client Identifier valid at the Authorization Server.
    pub client_id: String,

    /// Redirection URI to which the response will be sent.
    ///
    /// This field is required when using a response type returning an
    /// authorization code.
    ///
    /// This URI must have been pre-registered with the OpenID Provider.
    pub redirect_uri: Option<Url>,

    /// The scope of the access request.
    ///
    /// OpenID Connect requests must contain the `openid` scope value.
    pub scope: Scope,

    /// Opaque value used to maintain state between the request and the
    /// callback.
    pub state: Option<String>,

    /// The mechanism to be used for returning parameters from the Authorization
    /// Endpoint.
    ///
    /// This use of this parameter is not recommended when the Response Mode
    /// that would be requested is the default mode specified for the Response
    /// Type.
    pub response_mode: Option<ResponseMode>,

    /// String value used to associate a Client session with an ID Token, and to
    /// mitigate replay attacks.
    pub nonce: Option<String>,

    /// How the Authorization Server should display the authentication and
    /// consent user interface pages to the End-User.
    pub display: Option<Display>,

    /// Whether the Authorization Server should prompt the End-User for
    /// reauthentication and consent.
    ///
    /// If [`Prompt::None`] is used, it must be the only value.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, Prompt>>")]
    #[serde(default)]
    pub prompt: Option<Vec<Prompt>>,

    /// The allowable elapsed time in seconds since the last time the End-User
    /// was actively authenticated by the OpenID Provider.
    #[serde(default)]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub max_age: Option<NonZeroU32>,

    /// End-User's preferred languages and scripts for the user interface.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, LanguageTag>>")]
    #[serde(default)]
    pub ui_locales: Option<Vec<LanguageTag>>,

    /// ID Token previously issued by the Authorization Server being passed as a
    /// hint about the End-User's current or past authenticated session with the
    /// Client.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the login identifier the End-User
    /// might use to log in.
    pub login_hint: Option<String>,

    /// Requested Authentication Context Class Reference values.
    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, String>>")]
    #[serde(default)]
    pub acr_values: Option<HashSet<String>>,

    /// A JWT that contains the request's parameter values, called a [Request
    /// Object].
    ///
    /// [Request Object]: https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
    pub request: Option<String>,

    /// A URI referencing a [Request Object] or a [Pushed Authorization
    /// Request].
    ///
    /// [Request Object]: https://openid.net/specs/openid-connect-core-1_0.html#RequestUriParameter
    /// [Pushed Authorization Request]: https://datatracker.ietf.org/doc/html/rfc9126
    pub request_uri: Option<Url>,

    /// A JSON object containing the Client Metadata when interacting with a
    /// [Self-Issued OpenID Provider].
    ///
    /// [Self-Issued OpenID Provider]: https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
    pub registration: Option<String>,
}

impl AuthorizationRequest {
    /// Creates a basic `AuthorizationRequest`.
    #[must_use]
    pub fn new(response_type: ResponseType, client_id: String, scope: Scope) -> Self {
        Self {
            response_type,
            client_id,
            redirect_uri: None,
            scope,
            state: None,
            response_mode: None,
            nonce: None,
            display: None,
            prompt: None,
            max_age: None,
            ui_locales: None,
            id_token_hint: None,
            login_hint: None,
            acr_values: None,
            request: None,
            request_uri: None,
            registration: None,
        }
    }
}

impl fmt::Debug for AuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationRequest")
            .field("response_type", &self.response_type)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("response_mode", &self.response_mode)
            .field("display", &self.display)
            .field("prompt", &self.prompt)
            .field("max_age", &self.max_age)
            .field("ui_locales", &self.ui_locales)
            .field("login_hint", &self.login_hint)
            .field("acr_values", &self.acr_values)
            .field("request", &self.request)
            .field("request_uri", &self.request_uri)
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}

/// A successful response from the [Authorization Endpoint].
///
/// [Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
#[skip_serializing_none]
#[serde_as]
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AuthorizationResponse {
    /// The authorization code generated by the authorization server.
    pub code: Option<String>,

    /// The access token to access the requested scope.
    pub access_token: Option<String>,

    /// The type of the access token.
    pub token_type: Option<OAuthAccessTokenType>,

    /// ID Token value associated with the authenticated session.
    pub id_token: Option<String>,

    /// The duration for which the access token is valid.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expires_in: Option<Duration>,
}

impl fmt::Debug for AuthorizationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationResponse")
            .field("token_type", &self.token_type)
            .field("id_token", &self.id_token)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// A request to the [Device Authorization Endpoint].
///
/// [Device Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc8628
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationRequest {
    /// The scope of the access request.
    pub scope: Option<Scope>,
}

/// The default value of the `interval` between polling requests, if it is not
/// set.
pub const DEFAULT_DEVICE_AUTHORIZATION_INTERVAL: Duration = Duration::microseconds(5 * 1000 * 1000);

/// A successful response from the [Device Authorization Endpoint].
///
/// [Device Authorization Endpoint]: https://www.rfc-editor.org/rfc/rfc8628
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code.
    pub device_code: String,

    /// The end-user verification code.
    pub user_code: String,

    /// The end-user verification URI on the authorization server.
    ///
    /// The URI should be short and easy to remember as end users will be asked
    /// to manually type it into their user agent.
    pub verification_uri: Url,

    /// A verification URI that includes the `user_code` (or other information
    /// with the same function as the `user_code`), which is designed for
    /// non-textual transmission.
    pub verification_uri_complete: Option<Url>,

    /// The lifetime of the `device_code` and `user_code`.
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expires_in: Duration,

    /// The minimum amount of time in seconds that the client should wait
    /// between polling requests to the token endpoint.
    ///
    /// Defaults to [`DEFAULT_DEVICE_AUTHORIZATION_INTERVAL`].
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub interval: Option<Duration>,
}

impl DeviceAuthorizationResponse {
    /// The minimum amount of time in seconds that the client should wait
    /// between polling requests to the token endpoint.
    ///
    /// Defaults to [`DEFAULT_DEVICE_AUTHORIZATION_INTERVAL`].
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
            .unwrap_or(DEFAULT_DEVICE_AUTHORIZATION_INTERVAL)
    }
}

impl fmt::Debug for DeviceAuthorizationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceAuthorizationResponse")
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

/// A request to the [Token Endpoint] for the [Authorization Code] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Authorization Code]: https://www.rfc-editor.org/rfc/rfc6749#section-4.1
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    /// The authorization code that was returned from the authorization
    /// endpoint.
    pub code: String,

    /// The `redirect_uri` that was included in the authorization request.
    ///
    /// This field must match exactly the value passed to the authorization
    /// endpoint.
    pub redirect_uri: Option<Url>,

    /// The code verifier that matches the code challenge that was sent to the
    /// authorization endpoint.
    // TODO: move this somehow in the pkce module
    pub code_verifier: Option<String>,
}

impl fmt::Debug for AuthorizationCodeGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationCodeGrant")
            .field("redirect_uri", &self.redirect_uri)
            .finish_non_exhaustive()
    }
}

/// A request to the [Token Endpoint] for [refreshing an access token].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [refreshing an access token]: https://www.rfc-editor.org/rfc/rfc6749#section-6
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RefreshTokenGrant {
    /// The refresh token issued to the client.
    pub refresh_token: String,

    /// The scope of the access request.
    ///
    /// The requested scope must not include any scope not originally granted by
    /// the resource owner, and if omitted is treated as equal to the scope
    /// originally granted by the resource owner.
    pub scope: Option<Scope>,
}

impl fmt::Debug for RefreshTokenGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshTokenGrant")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// A request to the [Token Endpoint] for the [Client Credentials] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Client Credentials]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentialsGrant {
    /// The scope of the access request.
    pub scope: Option<Scope>,
}

/// A request to the [Token Endpoint] for the [Device Authorization] grant type.
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
/// [Device Authorization]: https://www.rfc-editor.org/rfc/rfc8628
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeviceCodeGrant {
    /// The device verification code, from the device authorization response.
    pub device_code: String,
}

impl fmt::Debug for DeviceCodeGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCodeGrant").finish_non_exhaustive()
    }
}

/// All possible values for the `grant_type` parameter.
#[derive(
    Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, SerializeDisplay, DeserializeFromStr,
)]
pub enum GrantType {
    /// [`authorization_code`](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)
    AuthorizationCode,

    /// [`refresh_token`](https://www.rfc-editor.org/rfc/rfc6749#section-6)
    RefreshToken,

    /// [`implicit`](https://www.rfc-editor.org/rfc/rfc6749#section-4.2)
    Implicit,

    /// [`client_credentials`](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)
    ClientCredentials,

    /// [`password`](https://www.rfc-editor.org/rfc/rfc6749#section-4.3)
    Password,

    /// [`urn:ietf:params:oauth:grant-type:device_code`](https://www.rfc-editor.org/rfc/rfc8628)
    DeviceCode,

    /// [`https://datatracker.ietf.org/doc/html/rfc7523#section-2.1`](https://www.rfc-editor.org/rfc/rfc7523#section-2.1)
    JwtBearer,

    /// [`urn:openid:params:grant-type:ciba`](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
    ClientInitiatedBackchannelAuthentication,

    /// An unknown value.
    Unknown(String),
}

impl core::fmt::Display for GrantType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GrantType::AuthorizationCode => f.write_str("authorization_code"),
            GrantType::RefreshToken => f.write_str("refresh_token"),
            GrantType::Implicit => f.write_str("implicit"),
            GrantType::ClientCredentials => f.write_str("client_credentials"),
            GrantType::Password => f.write_str("password"),
            GrantType::DeviceCode => f.write_str("urn:ietf:params:oauth:grant-type:device_code"),
            GrantType::JwtBearer => f.write_str("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            GrantType::ClientInitiatedBackchannelAuthentication => {
                f.write_str("urn:openid:params:grant-type:ciba")
            }
            GrantType::Unknown(s) => f.write_str(s),
        }
    }
}

impl core::str::FromStr for GrantType {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "refresh_token" => Ok(GrantType::RefreshToken),
            "implicit" => Ok(GrantType::Implicit),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "password" => Ok(GrantType::Password),
            "urn:ietf:params:oauth:grant-type:device_code" => Ok(GrantType::DeviceCode),
            "urn:ietf:params:oauth:grant-type:jwt-bearer" => Ok(GrantType::JwtBearer),
            "urn:openid:params:grant-type:ciba" => {
                Ok(GrantType::ClientInitiatedBackchannelAuthentication)
            }
            s => Ok(GrantType::Unknown(s.to_owned())),
        }
    }
}

/// An enum representing the possible requests to the [Token Endpoint].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AccessTokenRequest {
    /// A request in the Authorization Code flow.
    AuthorizationCode(AuthorizationCodeGrant),

    /// A request to refresh an access token.
    RefreshToken(RefreshTokenGrant),

    /// A request in the Client Credentials flow.
    ClientCredentials(ClientCredentialsGrant),

    /// A request in the Device Code flow.
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode(DeviceCodeGrant),

    /// An unsupported request.
    #[serde(skip_serializing, other)]
    Unsupported,
}

impl AccessTokenRequest {
    /// Returns the string representation of the grant type of the request.
    #[must_use]
    pub fn grant_type(&self) -> &'static str {
        match self {
            Self::AuthorizationCode(_) => "authorization_code",
            Self::RefreshToken(_) => "refresh_token",
            Self::ClientCredentials(_) => "client_credentials",
            Self::DeviceCode(_) => "urn:ietf:params:oauth:grant-type:device_code",
            Self::Unsupported => "unsupported",
        }
    }
}

/// A successful response from the [Token Endpoint].
///
/// [Token Endpoint]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AccessTokenResponse {
    /// The access token to access the requested scope.
    pub access_token: String,

    /// The token to refresh the access token when it expires.
    pub refresh_token: Option<String>,

    /// ID Token value associated with the authenticated session.
    // TODO: this should be somewhere else
    pub id_token: Option<String>,

    /// The type of the access token.
    pub token_type: OAuthAccessTokenType,

    /// The duration for which the access token is valid.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expires_in: Option<Duration>,

    /// The scope of the access token.
    pub scope: Option<Scope>,
}

impl AccessTokenResponse {
    /// Creates a new `AccessTokenResponse` with the given access token.
    #[must_use]
    pub fn new(access_token: String) -> AccessTokenResponse {
        AccessTokenResponse {
            access_token,
            refresh_token: None,
            id_token: None,
            token_type: OAuthAccessTokenType::Bearer,
            expires_in: None,
            scope: None,
        }
    }

    /// Adds a refresh token to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_refresh_token(mut self, refresh_token: String) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    /// Adds an ID token to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_id_token(mut self, id_token: String) -> Self {
        self.id_token = Some(id_token);
        self
    }

    /// Adds a scope to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Adds an expiration duration to an `AccessTokenResponse`.
    #[must_use]
    pub fn with_expires_in(mut self, expires_in: Duration) -> Self {
        self.expires_in = Some(expires_in);
        self
    }
}

impl fmt::Debug for AccessTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessTokenResponse")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// A request to the [Introspection Endpoint].
///
/// [Introspection Endpoint]: https://www.rfc-editor.org/rfc/rfc7662#section-2
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct IntrospectionRequest {
    /// The value of the token.
    pub token: String,

    /// A hint about the type of the token submitted for introspection.
    pub token_type_hint: Option<OAuthTokenTypeHint>,
}

impl fmt::Debug for IntrospectionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntrospectionRequest")
            .field("token_type_hint", &self.token_type_hint)
            .finish_non_exhaustive()
    }
}

/// A successful response from the [Introspection Endpoint].
///
/// [Introspection Endpoint]: https://www.rfc-editor.org/rfc/rfc7662#section-2
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct IntrospectionResponse {
    /// Whether or not the presented token is currently active.
    pub active: bool,

    /// The scope associated with the token.
    pub scope: Option<Scope>,

    /// Client identifier for the OAuth 2.0 client that requested this token.
    pub client_id: Option<String>,

    /// Human-readable identifier for the resource owner who authorized this
    /// token.
    pub username: Option<String>,

    /// Type of the token.
    pub token_type: Option<OAuthTokenTypeHint>,

    /// Timestamp indicating when the token will expire.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub exp: Option<DateTime<Utc>>,

    /// Relative timestamp indicating when the token will expire,
    /// in seconds from the current instant.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub expires_in: Option<Duration>,

    /// Timestamp indicating when the token was issued.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub iat: Option<DateTime<Utc>>,

    /// Timestamp indicating when the token is not to be used before.
    #[serde_as(as = "Option<TimestampSeconds>")]
    pub nbf: Option<DateTime<Utc>>,

    /// Subject of the token.
    pub sub: Option<String>,

    /// Intended audience of the token.
    pub aud: Option<String>,

    /// Issuer of the token.
    pub iss: Option<String>,

    /// String identifier for the token.
    pub jti: Option<String>,

    /// MAS extension: explicit device ID
    pub device_id: Option<String>,
}

/// A request to the [Revocation Endpoint].
///
/// [Revocation Endpoint]: https://www.rfc-editor.org/rfc/rfc7009#section-2
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RevocationRequest {
    /// The value of the token.
    pub token: String,

    /// A hint about the type of the token submitted for introspection.
    pub token_type_hint: Option<OAuthTokenTypeHint>,
}

impl fmt::Debug for RevocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationRequest")
            .field("token_type_hint", &self.token_type_hint)
            .finish_non_exhaustive()
    }
}

/// A successful response from the [Pushed Authorization Request Endpoint].
///
/// Note that there is no request type because it is by definition the same as
/// [`AuthorizationRequest`].
///
/// [Pushed Authorization Request Endpoint]: https://datatracker.ietf.org/doc/html/rfc9126
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PushedAuthorizationResponse {
    /// The `request_uri` to use for the request to the authorization endpoint.
    pub request_uri: String,

    /// The duration for which the request URI is valid.
    #[serde_as(as = "DurationSeconds<i64>")]
    pub expires_in: Duration,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{scope::OPENID, test_utils::assert_serde_json};

    #[test]
    fn serde_refresh_token_grant() {
        let expected = json!({
            "grant_type": "refresh_token",
            "refresh_token": "abcd",
            "scope": "openid",
        });

        // TODO: insert multiple scopes and test it. It's a bit tricky to test since
        // HashSet have no guarantees regarding the ordering of items, so right
        // now the output is unstable.
        let scope: Option<Scope> = Some(vec![OPENID].into_iter().collect());

        let req = AccessTokenRequest::RefreshToken(RefreshTokenGrant {
            refresh_token: "abcd".into(),
            scope,
        });

        assert_serde_json(&req, expected);
    }

    #[test]
    fn serde_authorization_code_grant() {
        let expected = json!({
            "grant_type": "authorization_code",
            "code": "abcd",
            "redirect_uri": "https://example.com/redirect",
        });

        let req = AccessTokenRequest::AuthorizationCode(AuthorizationCodeGrant {
            code: "abcd".into(),
            redirect_uri: Some("https://example.com/redirect".parse().unwrap()),
            code_verifier: None,
        });

        assert_serde_json(&req, expected);
    }

    #[test]
    fn serialize_grant_type() {
        assert_eq!(
            serde_json::to_string(&GrantType::AuthorizationCode).unwrap(),
            "\"authorization_code\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::RefreshToken).unwrap(),
            "\"refresh_token\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::Implicit).unwrap(),
            "\"implicit\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::ClientCredentials).unwrap(),
            "\"client_credentials\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::Password).unwrap(),
            "\"password\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::DeviceCode).unwrap(),
            "\"urn:ietf:params:oauth:grant-type:device_code\""
        );
        assert_eq!(
            serde_json::to_string(&GrantType::ClientInitiatedBackchannelAuthentication).unwrap(),
            "\"urn:openid:params:grant-type:ciba\""
        );
    }

    #[test]
    fn deserialize_grant_type() {
        assert_eq!(
            serde_json::from_str::<GrantType>("\"authorization_code\"").unwrap(),
            GrantType::AuthorizationCode
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"refresh_token\"").unwrap(),
            GrantType::RefreshToken
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"implicit\"").unwrap(),
            GrantType::Implicit
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"client_credentials\"").unwrap(),
            GrantType::ClientCredentials
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"password\"").unwrap(),
            GrantType::Password
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"urn:ietf:params:oauth:grant-type:device_code\"")
                .unwrap(),
            GrantType::DeviceCode
        );
        assert_eq!(
            serde_json::from_str::<GrantType>("\"urn:openid:params:grant-type:ciba\"").unwrap(),
            GrantType::ClientInitiatedBackchannelAuthentication
        );
    }

    #[test]
    fn serialize_response_mode() {
        assert_eq!(
            serde_json::to_string(&ResponseMode::Query).unwrap(),
            "\"query\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseMode::Fragment).unwrap(),
            "\"fragment\""
        );
        assert_eq!(
            serde_json::to_string(&ResponseMode::FormPost).unwrap(),
            "\"form_post\""
        );
    }

    #[test]
    fn deserialize_response_mode() {
        assert_eq!(
            serde_json::from_str::<ResponseMode>("\"query\"").unwrap(),
            ResponseMode::Query
        );
        assert_eq!(
            serde_json::from_str::<ResponseMode>("\"fragment\"").unwrap(),
            ResponseMode::Fragment
        );
        assert_eq!(
            serde_json::from_str::<ResponseMode>("\"form_post\"").unwrap(),
            ResponseMode::FormPost
        );
    }

    #[test]
    fn serialize_display() {
        assert_eq!(serde_json::to_string(&Display::Page).unwrap(), "\"page\"");
        assert_eq!(serde_json::to_string(&Display::Popup).unwrap(), "\"popup\"");
        assert_eq!(serde_json::to_string(&Display::Touch).unwrap(), "\"touch\"");
        assert_eq!(serde_json::to_string(&Display::Wap).unwrap(), "\"wap\"");
    }

    #[test]
    fn deserialize_display() {
        assert_eq!(
            serde_json::from_str::<Display>("\"page\"").unwrap(),
            Display::Page
        );
        assert_eq!(
            serde_json::from_str::<Display>("\"popup\"").unwrap(),
            Display::Popup
        );
        assert_eq!(
            serde_json::from_str::<Display>("\"touch\"").unwrap(),
            Display::Touch
        );
        assert_eq!(
            serde_json::from_str::<Display>("\"wap\"").unwrap(),
            Display::Wap
        );
    }

    #[test]
    fn serialize_prompt() {
        assert_eq!(serde_json::to_string(&Prompt::None).unwrap(), "\"none\"");
        assert_eq!(serde_json::to_string(&Prompt::Login).unwrap(), "\"login\"");
        assert_eq!(
            serde_json::to_string(&Prompt::Consent).unwrap(),
            "\"consent\""
        );
        assert_eq!(
            serde_json::to_string(&Prompt::SelectAccount).unwrap(),
            "\"select_account\""
        );
        assert_eq!(
            serde_json::to_string(&Prompt::Create).unwrap(),
            "\"create\""
        );
    }

    #[test]
    fn deserialize_prompt() {
        assert_eq!(
            serde_json::from_str::<Prompt>("\"none\"").unwrap(),
            Prompt::None
        );
        assert_eq!(
            serde_json::from_str::<Prompt>("\"login\"").unwrap(),
            Prompt::Login
        );
        assert_eq!(
            serde_json::from_str::<Prompt>("\"consent\"").unwrap(),
            Prompt::Consent
        );
        assert_eq!(
            serde_json::from_str::<Prompt>("\"select_account\"").unwrap(),
            Prompt::SelectAccount
        );
        assert_eq!(
            serde_json::from_str::<Prompt>("\"create\"").unwrap(),
            Prompt::Create
        );
    }
}
