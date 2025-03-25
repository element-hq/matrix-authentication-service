// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::{DateTime, Utc};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_jose::jwk::PublicJsonWebKeySet;
use oauth2_types::{
    oidc::ApplicationType,
    registration::{ClientMetadata, Localized},
    requests::GrantType,
};
use rand::RngCore;
use serde::Serialize;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JwksOrJwksUri {
    /// Client's JSON Web Key Set document, passed by value.
    Jwks(PublicJsonWebKeySet),

    /// URL for the Client's JSON Web Key Set document.
    JwksUri(Url),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Client {
    pub id: Ulid,

    /// Client identifier
    pub client_id: String,

    /// Hash of the client metadata
    pub metadata_digest: Option<String>,

    pub encrypted_client_secret: Option<String>,

    pub application_type: Option<ApplicationType>,

    /// Array of Redirection URI values used by the Client
    pub redirect_uris: Vec<Url>,

    /// Array containing a list of the OAuth 2.0 Grant Types that the Client is
    /// declaring that it will restrict itself to using.
    pub grant_types: Vec<GrantType>,

    /// Name of the Client to be presented to the End-User
    pub client_name: Option<String>, // TODO: translations

    /// URL that references a logo for the Client application
    pub logo_uri: Option<Url>, // TODO: translations

    /// URL of the home page of the Client
    pub client_uri: Option<Url>, // TODO: translations

    /// URL that the Relying Party Client provides to the End-User to read about
    /// the how the profile data will be used
    pub policy_uri: Option<Url>, // TODO: translations

    /// URL that the Relying Party Client provides to the End-User to read about
    /// the Relying Party's terms of service
    pub tos_uri: Option<Url>, // TODO: translations

    pub jwks: Option<JwksOrJwksUri>,

    /// JWS alg algorithm REQUIRED for signing the ID Token issued to this
    /// Client
    pub id_token_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// JWS alg algorithm REQUIRED for signing `UserInfo` Responses.
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// Requested authentication method for the token endpoint
    pub token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,

    /// JWS alg algorithm that MUST be used for signing the JWT used to
    /// authenticate the Client at the Token Endpoint for the `private_key_jwt`
    /// and `client_secret_jwt` authentication methods
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    /// URI using the https scheme that a third party can use to initiate a
    /// login by the RP
    pub initiate_login_uri: Option<Url>,
}

#[derive(Debug, Error)]
pub enum InvalidRedirectUriError {
    #[error("redirect_uri is not allowed for this client")]
    NotAllowed,

    #[error("multiple redirect_uris registered for this client")]
    MultipleRegistered,

    #[error("client has no redirect_uri registered")]
    NoneRegistered,
}

impl Client {
    /// Determine which redirect URI to use for the given request.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    ///  - no URL was given but multiple redirect URIs are registered,
    ///  - no URL was registered, or
    ///  - the given URL is not registered
    pub fn resolve_redirect_uri<'a>(
        &'a self,
        redirect_uri: &'a Option<Url>,
    ) -> Result<&'a Url, InvalidRedirectUriError> {
        match (&self.redirect_uris[..], redirect_uri) {
            ([], _) => Err(InvalidRedirectUriError::NoneRegistered),
            ([one], None) => Ok(one),
            (_, None) => Err(InvalidRedirectUriError::MultipleRegistered),
            (uris, Some(uri)) if uri_matches_one_of(uri, uris) => Ok(uri),
            _ => Err(InvalidRedirectUriError::NotAllowed),
        }
    }

    /// Create a client metadata object for this client
    #[must_use]
    pub fn into_metadata(self) -> ClientMetadata {
        let (jwks, jwks_uri) = match self.jwks {
            Some(JwksOrJwksUri::Jwks(jwks)) => (Some(jwks), None),
            Some(JwksOrJwksUri::JwksUri(jwks_uri)) => (None, Some(jwks_uri)),
            _ => (None, None),
        };
        ClientMetadata {
            redirect_uris: Some(self.redirect_uris.clone()),
            response_types: None,
            grant_types: Some(self.grant_types.clone()),
            application_type: self.application_type.clone(),
            client_name: self.client_name.map(|n| Localized::new(n, [])),
            logo_uri: self.logo_uri.map(|n| Localized::new(n, [])),
            client_uri: self.client_uri.map(|n| Localized::new(n, [])),
            policy_uri: self.policy_uri.map(|n| Localized::new(n, [])),
            tos_uri: self.tos_uri.map(|n| Localized::new(n, [])),
            jwks_uri,
            jwks,
            id_token_signed_response_alg: self.id_token_signed_response_alg,
            userinfo_signed_response_alg: self.userinfo_signed_response_alg,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            token_endpoint_auth_signing_alg: self.token_endpoint_auth_signing_alg,
            initiate_login_uri: self.initiate_login_uri,
            contacts: None,
            software_id: None,
            software_version: None,
            sector_identifier_uri: None,
            subject_type: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            default_max_age: None,
            require_auth_time: None,
            default_acr_values: None,
            request_uris: None,
            require_signed_request_object: None,
            require_pushed_authorization_requests: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            post_logout_redirect_uris: None,
        }
    }

    #[doc(hidden)]
    pub fn samples(now: DateTime<Utc>, rng: &mut impl RngCore) -> Vec<Client> {
        vec![
            // A client with all the URIs set
            Self {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                client_id: "client1".to_owned(),
                metadata_digest: None,
                encrypted_client_secret: None,
                application_type: Some(ApplicationType::Web),
                redirect_uris: vec![
                    Url::parse("https://client1.example.com/redirect").unwrap(),
                    Url::parse("https://client1.example.com/redirect2").unwrap(),
                ],
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                client_name: Some("Client 1".to_owned()),
                client_uri: Some(Url::parse("https://client1.example.com").unwrap()),
                logo_uri: Some(Url::parse("https://client1.example.com/logo.png").unwrap()),
                tos_uri: Some(Url::parse("https://client1.example.com/tos").unwrap()),
                policy_uri: Some(Url::parse("https://client1.example.com/policy").unwrap()),
                initiate_login_uri: Some(
                    Url::parse("https://client1.example.com/initiate-login").unwrap(),
                ),
                token_endpoint_auth_method: Some(OAuthClientAuthenticationMethod::None),
                token_endpoint_auth_signing_alg: None,
                id_token_signed_response_alg: None,
                userinfo_signed_response_alg: None,
                jwks: None,
            },
            // Another client without any URIs set
            Self {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                client_id: "client2".to_owned(),
                metadata_digest: None,
                encrypted_client_secret: None,
                application_type: Some(ApplicationType::Native),
                redirect_uris: vec![Url::parse("https://client2.example.com/redirect").unwrap()],
                grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
                client_name: None,
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                initiate_login_uri: None,
                token_endpoint_auth_method: None,
                token_endpoint_auth_signing_alg: None,
                id_token_signed_response_alg: None,
                userinfo_signed_response_alg: None,
                jwks: None,
            },
        ]
    }
}

/// The hosts that match the loopback interface.
const LOCAL_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

/// Whether the given URI matches one of the registered URIs.
///
/// If the URI host is one if `localhost`, `127.0.0.1` or `[::1]`, any port is
/// accepted.
fn uri_matches_one_of(uri: &Url, registered_uris: &[Url]) -> bool {
    if LOCAL_HOSTS.contains(&uri.host_str().unwrap_or_default()) {
        let mut uri = uri.clone();
        // Try matching without the port first
        if uri.set_port(None).is_ok() && registered_uris.contains(&uri) {
            return true;
        }
    }

    registered_uris.contains(uri)
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    #[test]
    fn test_uri_matches_one_of() {
        let registered_uris = &[
            Url::parse("http://127.0.0.1").unwrap(),
            Url::parse("https://example.org").unwrap(),
        ];

        // Non-loopback interface URIs.
        assert!(uri_matches_one_of(
            &Url::parse("https://example.org").unwrap(),
            registered_uris
        ));
        assert!(!uri_matches_one_of(
            &Url::parse("https://example.org:8080").unwrap(),
            registered_uris
        ));

        // Loopback interface URIS.
        assert!(uri_matches_one_of(
            &Url::parse("http://127.0.0.1").unwrap(),
            registered_uris
        ));
        assert!(uri_matches_one_of(
            &Url::parse("http://127.0.0.1:8080").unwrap(),
            registered_uris
        ));
        assert!(!uri_matches_one_of(
            &Url::parse("http://localhost").unwrap(),
            registered_uris
        ));
    }
}
