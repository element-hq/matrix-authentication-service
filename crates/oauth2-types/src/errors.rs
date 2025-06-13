// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Error types returned by an authorization server.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// A client error returned by an authorization server.
///
/// To construct this with a default description for the error code, use its
/// `From<ClientErrorCode>` implementation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientError {
    /// The error code.
    pub error: ClientErrorCode,

    /// A human-readable description of the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<Cow<'static, str>>,
}

impl ClientError {
    /// Creates a new `ClientError` with the given error code and description.
    #[must_use]
    pub const fn new(error: ClientErrorCode, error_description: &'static str) -> Self {
        Self {
            error,
            error_description: Some(Cow::Borrowed(error_description)),
        }
    }

    /// Changes the description of this `ClientError` with the given `String`.
    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.error_description = Some(Cow::Owned(description));
        self
    }
}

impl From<ClientErrorCode> for ClientError {
    fn from(error: ClientErrorCode) -> Self {
        let desc = error.default_description();
        Self::new(error, desc)
    }
}

/// Client error codes defined in OAuth2.0, OpenID Connect and their extensions.
#[derive(Debug, Clone, PartialEq, Eq, SerializeDisplay, DeserializeFromStr)]
pub enum ClientErrorCode {
    /// `invalid_request`
    ///
    /// The request is missing a required parameter, includes an invalid
    /// parameter value, includes a parameter more than once, or is otherwise
    /// malformed.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    InvalidRequest,

    /// `invalid_client`
    ///
    /// Client authentication failed (e.g., unknown client, no client
    /// authentication included, or unsupported authentication method).
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    InvalidClient,

    /// `invalid_grant`
    ///
    /// The provided authorization grant (e.g., authorization code, resource
    /// owner credentials) or refresh token is invalid, expired, revoked, does
    /// not match the redirection URI used in the authorization request, or was
    /// issued to another client.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    InvalidGrant,

    /// `unauthorized_client`
    ///
    /// The authenticated client is not authorized to use this authorization
    /// grant type.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    UnauthorizedClient,

    /// `unsupported_grant_type`
    ///
    /// The authorization grant type is not supported by the authorization
    /// server.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-5.2).
    UnsupportedGrantType,

    /// `access_denied`
    ///
    /// The resource owner or authorization server denied the request.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    AccessDenied,

    /// `unsupported_response_type`
    ///
    /// The authorization server does not support obtaining an authorization
    /// code using this method.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    UnsupportedResponseType,

    /// `invalid_scope`
    ///
    /// The requested scope is invalid, unknown, malformed, or exceeds the scope
    /// granted by the resource owner.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    InvalidScope,

    /// `server_error`
    ///
    /// The authorization server encountered an unexpected condition that
    /// prevented it from fulfilling the request.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    ServerError,

    /// `temporarily_unavailable`
    ///
    /// The authorization server is currently unable to handle the request due
    /// to a temporary overloading or maintenance of the server.
    ///
    /// From [RFC6749](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1).
    TemporarilyUnavailable,

    /// `interaction_required`
    ///
    /// The authorization server requires end-user interaction of some form to
    /// proceed.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    InteractionRequired,

    /// `login_required`
    ///
    /// The authorization server requires end-user authentication.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    LoginRequired,

    /// `account_selection_required`
    ///
    /// The end-user is required to select a session at the authorization
    /// server.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    AccountSelectionRequired,

    /// `consent_required`
    ///
    /// The authorization server requires end-user consent.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    ConsentRequired,

    /// `invalid_request_uri`
    ///
    /// The `request_uri` in the authorization request returns an error or
    /// contains invalid data.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    InvalidRequestUri,

    /// `invalid_request_object`
    ///
    /// The request parameter contains an invalid request object.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    InvalidRequestObject,

    /// `request_not_supported`
    ///
    /// The authorization server does not support use of the `request`
    /// parameter.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    RequestNotSupported,

    /// `request_uri_not_supported`
    ///
    /// The authorization server does not support use of the `request_uri`
    /// parameter.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    RequestUriNotSupported,

    /// `registration_not_supported`
    ///
    /// The authorization server does not support use of the `registration`
    /// parameter.
    ///
    /// From [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthError).
    RegistrationNotSupported,

    /// `invalid_redirect_uri`
    ///
    /// The value of one or more redirection URIs is invalid.
    ///
    /// From [RFC7591](https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2).
    InvalidRedirectUri,

    /// `invalid_client_metadata`
    ///
    /// The value of one of the client metadata fields is invalid and the server
    /// has rejected this request.
    ///
    /// From [RFC7591](https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2).
    InvalidClientMetadata,

    /// `authorization_pending`
    ///
    /// The authorization request is still pending as the end user hasn't yet
    /// completed the user-interaction steps.
    ///
    /// The client should repeat the access token request to the token endpoint
    /// (a process known as polling).  Before each new request, the client
    /// must wait at least the number of seconds specified by the `interval`
    /// parameter of the device authorization response, or 5 seconds if none was
    /// provided, and respect any increase in the polling interval required
    /// by the [`ClientErrorCode::SlowDown`] error.
    ///
    /// From [RFC8628](https://www.rfc-editor.org/rfc/rfc8628#section-3.5).
    AuthorizationPending,

    /// `slow_down`
    ///
    /// A variant of [`ClientErrorCode::AuthorizationPending`], the
    /// authorization request is still pending and polling should continue,
    /// but the interval must be increased by 5 seconds for this and all
    /// subsequent requests.
    ///
    /// From [RFC8628](https://www.rfc-editor.org/rfc/rfc8628#section-3.5).
    SlowDown,

    /// `expired_token`
    ///
    /// The `device_code` has expired, and the device authorization session has
    /// concluded.
    ///
    /// The client may commence a new device authorization request but should
    /// wait for user interaction before restarting to avoid unnecessary
    /// polling.
    ///
    /// From [RFC8628](https://www.rfc-editor.org/rfc/rfc8628#section-3.5).
    ExpiredToken,

    /// `unsupported_token_type`
    ///
    /// The authorization server does not support the revocation of the
    /// presented token type.  That is, the client tried to revoke an access
    /// token on a server not supporting this feature.
    ///
    /// From [RFC7009](https://www.rfc-editor.org/rfc/rfc7009#section-2.2.1).
    UnsupportedTokenType,

    /// Another error code.
    Unknown(String),
}

impl core::fmt::Display for ClientErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientErrorCode::InvalidRequest => f.write_str("invalid_request"),
            ClientErrorCode::InvalidClient => f.write_str("invalid_client"),
            ClientErrorCode::InvalidGrant => f.write_str("invalid_grant"),
            ClientErrorCode::UnauthorizedClient => f.write_str("unauthorized_client"),
            ClientErrorCode::UnsupportedGrantType => f.write_str("unsupported_grant_type"),
            ClientErrorCode::AccessDenied => f.write_str("access_denied"),
            ClientErrorCode::UnsupportedResponseType => f.write_str("unsupported_response_type"),
            ClientErrorCode::InvalidScope => f.write_str("invalid_scope"),
            ClientErrorCode::ServerError => f.write_str("server_error"),
            ClientErrorCode::TemporarilyUnavailable => f.write_str("temporarily_unavailable"),
            ClientErrorCode::InteractionRequired => f.write_str("interaction_required"),
            ClientErrorCode::LoginRequired => f.write_str("login_required"),
            ClientErrorCode::AccountSelectionRequired => f.write_str("account_selection_required"),
            ClientErrorCode::ConsentRequired => f.write_str("consent_required"),
            ClientErrorCode::InvalidRequestUri => f.write_str("invalid_request_uri"),
            ClientErrorCode::InvalidRequestObject => f.write_str("invalid_request_object"),
            ClientErrorCode::RequestNotSupported => f.write_str("request_not_supported"),
            ClientErrorCode::RequestUriNotSupported => f.write_str("request_uri_not_supported"),
            ClientErrorCode::RegistrationNotSupported => f.write_str("registration_not_supported"),
            ClientErrorCode::InvalidRedirectUri => f.write_str("invalid_redirect_uri"),
            ClientErrorCode::InvalidClientMetadata => f.write_str("invalid_client_metadata"),
            ClientErrorCode::AuthorizationPending => f.write_str("authorization_pending"),
            ClientErrorCode::SlowDown => f.write_str("slow_down"),
            ClientErrorCode::ExpiredToken => f.write_str("expired_token"),
            ClientErrorCode::UnsupportedTokenType => f.write_str("unsupported_token_type"),
            ClientErrorCode::Unknown(value) => f.write_str(value),
        }
    }
}

impl core::str::FromStr for ClientErrorCode {
    type Err = core::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "invalid_request" => Ok(ClientErrorCode::InvalidRequest),
            "invalid_client" => Ok(ClientErrorCode::InvalidClient),
            "invalid_grant" => Ok(ClientErrorCode::InvalidGrant),
            "unauthorized_client" => Ok(ClientErrorCode::UnauthorizedClient),
            "unsupported_grant_type" => Ok(ClientErrorCode::UnsupportedGrantType),
            "access_denied" => Ok(ClientErrorCode::AccessDenied),
            "unsupported_response_type" => Ok(ClientErrorCode::UnsupportedResponseType),
            "invalid_scope" => Ok(ClientErrorCode::InvalidScope),
            "server_error" => Ok(ClientErrorCode::ServerError),
            "temporarily_unavailable" => Ok(ClientErrorCode::TemporarilyUnavailable),
            "interaction_required" => Ok(ClientErrorCode::InteractionRequired),
            "login_required" => Ok(ClientErrorCode::LoginRequired),
            "account_selection_required" => Ok(ClientErrorCode::AccountSelectionRequired),
            "consent_required" => Ok(ClientErrorCode::ConsentRequired),
            "invalid_request_uri" => Ok(ClientErrorCode::InvalidRequestUri),
            "invalid_request_object" => Ok(ClientErrorCode::InvalidRequestObject),
            "request_not_supported" => Ok(ClientErrorCode::RequestNotSupported),
            "request_uri_not_supported" => Ok(ClientErrorCode::RequestUriNotSupported),
            "registration_not_supported" => Ok(ClientErrorCode::RegistrationNotSupported),
            "invalid_redirect_uri" => Ok(ClientErrorCode::InvalidRedirectUri),
            "invalid_client_metadata" => Ok(ClientErrorCode::InvalidClientMetadata),
            "authorization_pending" => Ok(ClientErrorCode::AuthorizationPending),
            "slow_down" => Ok(ClientErrorCode::SlowDown),
            "expired_token" => Ok(ClientErrorCode::ExpiredToken),
            "unsupported_token_type" => Ok(ClientErrorCode::UnsupportedTokenType),
            _ => Ok(ClientErrorCode::Unknown(s.to_owned())),
        }
    }
}

impl ClientErrorCode {
    /// Get the default description for this `ClientErrorCode`.
    ///
    /// Note that [`ClientErrorCode::Unknown`] returns an empty string.
    #[must_use]
    pub fn default_description(&self) -> &'static str {
        match self {
            ClientErrorCode::InvalidRequest => {
                "The request is missing a required parameter, includes an \
                invalid parameter value, includes a parameter more than once, \
                or is otherwise malformed."
            }
            ClientErrorCode::InvalidClient => "Client authentication failed.",
            ClientErrorCode::InvalidGrant => {
                "The provided access grant is invalid, expired, or revoked."
            }
            ClientErrorCode::UnauthorizedClient => {
                "The client is not authorized to request an access token using this method."
            }
            ClientErrorCode::UnsupportedGrantType => {
                "The authorization grant type is not supported by the authorization server."
            }
            ClientErrorCode::AccessDenied => {
                "The resource owner or authorization server denied the request."
            }
            ClientErrorCode::UnsupportedResponseType => {
                "The authorization server does not support obtaining an access \
                token using this method."
            }
            ClientErrorCode::InvalidScope => {
                "The requested scope is invalid, unknown, or malformed."
            }
            ClientErrorCode::ServerError => {
                "The authorization server encountered an unexpected condition \
                that prevented it from fulfilling the request."
            }
            ClientErrorCode::TemporarilyUnavailable => {
                "The authorization server is currently unable to handle the request \
                due to a temporary overloading or maintenance of the server."
            }
            ClientErrorCode::InteractionRequired => {
                "The Authorization Server requires End-User interaction of some form to proceed."
            }
            ClientErrorCode::LoginRequired => {
                "The Authorization Server requires End-User authentication."
            }
            ClientErrorCode::AccountSelectionRequired => {
                "The End-User is required to select a session at the Authorization Server."
            }
            ClientErrorCode::ConsentRequired => {
                "The Authorization Server requires End-User consent."
            }
            ClientErrorCode::InvalidRequestUri => {
                "The request_uri in the Authorization Request returns an error \
                or contains invalid data."
            }
            ClientErrorCode::InvalidRequestObject => {
                "The request parameter contains an invalid Request Object."
            }
            ClientErrorCode::RequestNotSupported => {
                "The provider does not support use of the request parameter."
            }
            ClientErrorCode::RequestUriNotSupported => {
                "The provider does not support use of the request_uri parameter."
            }
            ClientErrorCode::RegistrationNotSupported => {
                "The provider does not support use of the registration parameter."
            }
            ClientErrorCode::InvalidRedirectUri => {
                "The value of one or more redirection URIs is invalid."
            }
            ClientErrorCode::InvalidClientMetadata => {
                "The value of one of the client metadata fields is invalid"
            }
            ClientErrorCode::AuthorizationPending => "The authorization request is still pending",
            ClientErrorCode::SlowDown => {
                "The interval must be increased by 5 seconds for this and all subsequent requests"
            }
            ClientErrorCode::ExpiredToken => {
                "The \"device_code\" has expired, and the device authorization session has concluded"
            }
            ClientErrorCode::UnsupportedTokenType => {
                "The authorization server does not support the revocation of the presented token type."
            }
            ClientErrorCode::Unknown(_) => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_client_error_code() {
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidRequest).unwrap(),
            "\"invalid_request\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidClient).unwrap(),
            "\"invalid_client\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidGrant).unwrap(),
            "\"invalid_grant\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::UnauthorizedClient).unwrap(),
            "\"unauthorized_client\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::UnsupportedGrantType).unwrap(),
            "\"unsupported_grant_type\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::AccessDenied).unwrap(),
            "\"access_denied\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::UnsupportedResponseType).unwrap(),
            "\"unsupported_response_type\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidScope).unwrap(),
            "\"invalid_scope\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::ServerError).unwrap(),
            "\"server_error\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::TemporarilyUnavailable).unwrap(),
            "\"temporarily_unavailable\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InteractionRequired).unwrap(),
            "\"interaction_required\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::LoginRequired).unwrap(),
            "\"login_required\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::AccountSelectionRequired).unwrap(),
            "\"account_selection_required\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::ConsentRequired).unwrap(),
            "\"consent_required\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidRequestUri).unwrap(),
            "\"invalid_request_uri\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidRequestObject).unwrap(),
            "\"invalid_request_object\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::RequestNotSupported).unwrap(),
            "\"request_not_supported\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::RequestUriNotSupported).unwrap(),
            "\"request_uri_not_supported\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::RegistrationNotSupported).unwrap(),
            "\"registration_not_supported\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidRedirectUri).unwrap(),
            "\"invalid_redirect_uri\""
        );
        assert_eq!(
            serde_json::to_string(&ClientErrorCode::InvalidClientMetadata).unwrap(),
            "\"invalid_client_metadata\""
        );

        assert_eq!(
            serde_json::to_string(&ClientErrorCode::Unknown("unknown_error_code".to_owned()))
                .unwrap(),
            "\"unknown_error_code\""
        );
    }

    #[test]
    fn deserialize_client_error_code() {
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_request\"").unwrap(),
            ClientErrorCode::InvalidRequest
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_client\"").unwrap(),
            ClientErrorCode::InvalidClient
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_grant\"").unwrap(),
            ClientErrorCode::InvalidGrant
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"unauthorized_client\"").unwrap(),
            ClientErrorCode::UnauthorizedClient
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"unsupported_grant_type\"").unwrap(),
            ClientErrorCode::UnsupportedGrantType
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"access_denied\"").unwrap(),
            ClientErrorCode::AccessDenied
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"unsupported_response_type\"").unwrap(),
            ClientErrorCode::UnsupportedResponseType
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_scope\"").unwrap(),
            ClientErrorCode::InvalidScope
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"server_error\"").unwrap(),
            ClientErrorCode::ServerError
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"temporarily_unavailable\"").unwrap(),
            ClientErrorCode::TemporarilyUnavailable
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"interaction_required\"").unwrap(),
            ClientErrorCode::InteractionRequired
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"login_required\"").unwrap(),
            ClientErrorCode::LoginRequired
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"account_selection_required\"").unwrap(),
            ClientErrorCode::AccountSelectionRequired
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"consent_required\"").unwrap(),
            ClientErrorCode::ConsentRequired
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_request_uri\"").unwrap(),
            ClientErrorCode::InvalidRequestUri
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_request_object\"").unwrap(),
            ClientErrorCode::InvalidRequestObject
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"request_not_supported\"").unwrap(),
            ClientErrorCode::RequestNotSupported
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"request_uri_not_supported\"").unwrap(),
            ClientErrorCode::RequestUriNotSupported
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"registration_not_supported\"").unwrap(),
            ClientErrorCode::RegistrationNotSupported
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_redirect_uri\"").unwrap(),
            ClientErrorCode::InvalidRedirectUri
        );
        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"invalid_client_metadata\"").unwrap(),
            ClientErrorCode::InvalidClientMetadata
        );

        assert_eq!(
            serde_json::from_str::<ClientErrorCode>("\"unknown_error_code\"").unwrap(),
            ClientErrorCode::Unknown("unknown_error_code".to_owned())
        );
    }
}
