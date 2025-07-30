// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Types for [Dynamic Client Registration].
//!
//! [Dynamic Client Registration]: https://openid.net/specs/openid-connect-registration-1_0.html

use std::ops::Deref;

use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
use language_tags::LanguageTag;
use mas_iana::{
    jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg},
    oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod},
};
use mas_jose::jwk::PublicJsonWebKeySet;
use serde::{Deserialize, Serialize};
use serde_with::{TimestampSeconds, serde_as, skip_serializing_none};
use thiserror::Error;
use url::Url;

use crate::{
    oidc::{ApplicationType, SubjectType},
    requests::GrantType,
    response_type::ResponseType,
};

mod client_metadata_serde;
use client_metadata_serde::ClientMetadataSerdeHelper;

/// The default value of `response_types` if it is not set.
pub const DEFAULT_RESPONSE_TYPES: [OAuthAuthorizationEndpointResponseType; 1] =
    [OAuthAuthorizationEndpointResponseType::Code];

/// The default value of `grant_types` if it is not set.
pub const DEFAULT_GRANT_TYPES: &[GrantType] = &[GrantType::AuthorizationCode];

/// The default value of `application_type` if it is not set.
pub const DEFAULT_APPLICATION_TYPE: ApplicationType = ApplicationType::Web;

/// The default value of `token_endpoint_auth_method` if it is not set.
pub const DEFAULT_TOKEN_AUTH_METHOD: &OAuthClientAuthenticationMethod =
    &OAuthClientAuthenticationMethod::ClientSecretBasic;

/// The default value of `id_token_signed_response_alg` if it is not set.
pub const DEFAULT_SIGNING_ALGORITHM: &JsonWebSignatureAlg = &JsonWebSignatureAlg::Rs256;

/// The default value of `id_token_encrypted_response_enc` if it is not set.
pub const DEFAULT_ENCRYPTION_ENC_ALGORITHM: &JsonWebEncryptionEnc =
    &JsonWebEncryptionEnc::A128CbcHs256;

/// A collection of localized variants.
///
/// Always includes one non-localized variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Localized<T> {
    non_localized: T,
    localized: IndexMap<LanguageTag, T>,
}

impl<T> Localized<T> {
    /// Constructs a new `Localized` with the given non-localized and localized
    /// variants.
    pub fn new(non_localized: T, localized: impl IntoIterator<Item = (LanguageTag, T)>) -> Self {
        Self {
            non_localized,
            localized: localized.into_iter().collect(),
        }
    }

    /// Returns the number of variants.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.localized.len() + 1
    }

    /// Get the non-localized variant.
    pub fn non_localized(&self) -> &T {
        &self.non_localized
    }

    /// Get the non-localized variant.
    pub fn to_non_localized(self) -> T {
        self.non_localized
    }

    /// Get the variant corresponding to the given language, if it exists.
    pub fn get(&self, language: Option<&LanguageTag>) -> Option<&T> {
        match language {
            Some(lang) => self.localized.get(lang),
            None => Some(&self.non_localized),
        }
    }

    /// Get an iterator over the variants.
    pub fn iter(&self) -> impl Iterator<Item = (Option<&LanguageTag>, &T)> {
        Some(&self.non_localized)
            .into_iter()
            .map(|val| (None, val))
            .chain(self.localized.iter().map(|(lang, val)| (Some(lang), val)))
    }
}

impl<T> From<(T, IndexMap<LanguageTag, T>)> for Localized<T> {
    fn from(t: (T, IndexMap<LanguageTag, T>)) -> Self {
        Localized {
            non_localized: t.0,
            localized: t.1,
        }
    }
}

/// Client metadata, as described by the [IANA registry].
///
/// All the fields with a default value are accessible via methods.
///
/// [IANA registry]: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#client-metadata
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
#[serde(from = "ClientMetadataSerdeHelper", into = "ClientMetadataSerdeHelper")]
pub struct ClientMetadata {
    /// Array of redirection URIs for use in redirect-based flows such as the
    /// [authorization code flow].
    ///
    /// All the URIs used by the client in an authorization request's
    /// `redirect_uri` field must appear in this list.
    ///
    /// This field is required and the URIs must not contain a fragment.
    ///
    /// [authorization code flow]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
    pub redirect_uris: Option<Vec<Url>>,

    /// Array of the [OAuth 2.0 `response_type` values] that the client can use
    /// at the [authorization endpoint].
    ///
    /// All the types used by the client in an authorization request's
    /// `response_type` field must appear in this list.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_TYPES`].
    ///
    /// [OAuth 2.0 `response_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    /// [authorization endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
    pub response_types: Option<Vec<ResponseType>>,

    /// Array of [OAuth 2.0 `grant_type` values] that the client can use at the
    /// [token endpoint].
    ///
    /// The possible grant types depend on the response types. Declaring support
    /// for a grant type that is not compatible with the supported response
    /// types will trigger an error during validation.
    ///
    /// All the types used by the client in a token request's `grant_type` field
    /// must appear in this list.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES`].
    ///
    /// [OAuth 2.0 `grant_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    pub grant_types: Option<Vec<GrantType>>,

    /// The kind of the application.
    ///
    /// Defaults to [`DEFAULT_APPLICATION_TYPE`].
    pub application_type: Option<ApplicationType>,

    /// Array of e-mail addresses of people responsible for this client.
    pub contacts: Option<Vec<String>>,

    /// Name of the client to be presented to the end-user during authorization.
    pub client_name: Option<Localized<String>>,

    /// URL that references a logo for the client application.
    pub logo_uri: Option<Localized<Url>>,

    /// URL of the home page of the client.
    pub client_uri: Option<Localized<Url>>,

    /// URL that the client provides to the end-user to read about the how the
    /// profile data will be used.
    pub policy_uri: Option<Localized<Url>>,

    /// URL that the client provides to the end-user to read about the client's
    /// terms of service.
    pub tos_uri: Option<Localized<Url>>,

    /// URL for the client's [JWK] Set document.
    ///
    /// If the client signs requests to the server, it contains the signing
    /// key(s) the server uses to validate signatures from the client. The JWK
    /// Set may also contain the client's encryption keys(s), which are used by
    /// the server to encrypt responses to the client.
    ///
    /// This field is mutually exclusive with `jwks`.
    ///
    /// [JWK]: https://www.rfc-editor.org/rfc/rfc7517.html
    pub jwks_uri: Option<Url>,

    /// Client's [JWK] Set document, passed by value.
    ///
    /// The semantics of this field are the same as `jwks_uri`, other than that
    /// the JWK Set is passed by value, rather than by reference.
    ///
    /// This field is mutually exclusive with `jwks_uri`.
    ///
    /// [JWK]: https://www.rfc-editor.org/rfc/rfc7517.html
    pub jwks: Option<PublicJsonWebKeySet>,

    /// A unique identifier string assigned by the client developer or software
    /// publisher used by registration endpoints to identify the client software
    /// to be dynamically registered.
    ///
    /// It should remain the same for all instances and versions of the client
    /// software.
    pub software_id: Option<String>,

    /// A version identifier string for the client software identified by
    /// `software_id`.
    pub software_version: Option<String>,

    /// URL to be used in calculating pseudonymous identifiers by the OpenID
    /// Connect provider when [pairwise subject identifiers] are used.
    ///
    /// If present, this must use the `https` scheme.
    ///
    /// [pairwise subject identifiers]: https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
    pub sector_identifier_uri: Option<Url>,

    /// Subject type requested for responses to this client.
    ///
    /// This field must match one of the supported types by the provider.
    pub subject_type: Option<SubjectType>,

    /// Requested client authentication method for the [token endpoint].
    ///
    /// If this is set to [`OAuthClientAuthenticationMethod::PrivateKeyJwt`],
    /// one of the `jwks_uri` or `jwks` fields is required.
    ///
    /// Defaults to [`DEFAULT_TOKEN_AUTH_METHOD`].
    ///
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    pub token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,

    /// [JWS] `alg` algorithm that must be used for signing the [JWT] used to
    /// authenticate the client at the token endpoint.
    ///
    /// If this field is present, it must not be
    /// [`JsonWebSignatureAlg::None`]. This field is required if
    /// `token_endpoint_auth_method` is one of
    /// [`OAuthClientAuthenticationMethod::PrivateKeyJwt`] or
    /// [`OAuthClientAuthenticationMethod::ClientSecretJwt`].
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    /// [JWT]: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token
    pub token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,

    /// [JWS] `alg` algorithm required for signing the ID Token issued to this
    /// client.
    ///
    /// If this field is present, it must not be
    /// [`JsonWebSignatureAlg::None`], unless the client uses only response
    /// types that return no ID Token from the authorization endpoint.
    ///
    /// Defaults to [`DEFAULT_SIGNING_ALGORITHM`].
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    pub id_token_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// [JWE] `alg` algorithm required for encrypting the ID Token issued to
    /// this client.
    ///
    /// This field is required if `id_token_encrypted_response_enc` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub id_token_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    /// [JWE] `enc` algorithm required for encrypting the ID Token issued to
    /// this client.
    ///
    /// Defaults to [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] if
    /// `id_token_encrypted_response_alg` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub id_token_encrypted_response_enc: Option<JsonWebEncryptionEnc>,

    /// [JWS] `alg` algorithm required for signing user info responses.
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    pub userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// [JWE] `alg` algorithm required for encrypting user info responses.
    ///
    /// If `userinfo_signed_response_alg` is not provided, this field has no
    /// effect.
    ///
    /// This field is required if `userinfo_encrypted_response_enc` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub userinfo_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    /// [JWE] `enc` algorithm required for encrypting user info responses.
    ///
    /// If `userinfo_signed_response_alg` is not provided, this field has no
    /// effect.
    ///
    /// Defaults to [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] if
    /// `userinfo_encrypted_response_alg` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub userinfo_encrypted_response_enc: Option<JsonWebEncryptionEnc>,

    /// [JWS] `alg` algorithm that must be used for signing Request Objects sent
    /// to the provider.
    ///
    /// Defaults to any algorithm supported by the client and the provider.
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    pub request_object_signing_alg: Option<JsonWebSignatureAlg>,

    /// [JWE] `alg` algorithm the client is declaring that it may use for
    /// encrypting Request Objects sent to the provider.
    ///
    /// This field is required if `request_object_encryption_enc` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub request_object_encryption_alg: Option<JsonWebEncryptionAlg>,

    /// [JWE] `enc` algorithm the client is declaring that it may use for
    /// encrypting Request Objects sent to the provider.
    ///
    /// Defaults to [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] if
    /// `request_object_encryption_alg` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    pub request_object_encryption_enc: Option<JsonWebEncryptionEnc>,

    /// Default maximum authentication age.
    ///
    /// Specifies that the End-User must be actively authenticated if the
    /// end-user was authenticated longer ago than the specified number of
    /// seconds.
    ///
    /// The `max_age` request parameter overrides this default value.
    pub default_max_age: Option<Duration>,

    /// Whether the `auth_time` Claim in the ID Token is required.
    ///
    /// Defaults to `false`.
    pub require_auth_time: Option<bool>,

    /// Default requested Authentication Context Class Reference values.
    pub default_acr_values: Option<Vec<String>>,

    /// URI that a third party can use to [initiate a login by the client].
    ///
    /// If present, this must use the `https` scheme.
    ///
    /// [initiate a login by the client]: https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin
    pub initiate_login_uri: Option<Url>,

    /// `request_uri` values that are pre-registered by the client for use at
    /// the provider.
    ///
    /// Providers can require that `request_uri` values used be pre-registered
    /// with the `require_request_uri_registration` discovery parameter.
    ///
    /// Servers MAY cache the contents of the files referenced by these URIs and
    /// not retrieve them at the time they are used in a request. If the
    /// contents of the request file could ever change, these URI values should
    /// include the base64url encoded SHA-256 hash value of the file contents
    /// referenced by the URI as the value of the URI fragment. If the fragment
    /// value used for a URI changes, that signals the server that its cached
    /// value for that URI with the old fragment value is no longer valid.
    pub request_uris: Option<Vec<Url>>,

    /// Whether the client will only send authorization requests as [Request
    /// Objects].
    ///
    /// Defaults to `false`.
    ///
    /// [Request Object]: https://www.rfc-editor.org/rfc/rfc9101.html
    pub require_signed_request_object: Option<bool>,

    /// Whether the client will only send authorization requests via the [pushed
    /// authorization request endpoint].
    ///
    /// Defaults to `false`.
    ///
    /// [pushed authorization request endpoint]: https://www.rfc-editor.org/rfc/rfc9126.html
    pub require_pushed_authorization_requests: Option<bool>,

    /// [JWS] `alg` algorithm for signing responses of the [introspection
    /// endpoint].
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    /// [introspection endpoint]: https://www.rfc-editor.org/info/rfc7662
    pub introspection_signed_response_alg: Option<JsonWebSignatureAlg>,

    /// [JWE] `alg` algorithm for encrypting responses of the [introspection
    /// endpoint].
    ///
    /// If `introspection_signed_response_alg` is not provided, this field has
    /// no effect.
    ///
    /// This field is required if `introspection_encrypted_response_enc` is
    /// provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    /// [introspection endpoint]: https://www.rfc-editor.org/info/rfc7662
    pub introspection_encrypted_response_alg: Option<JsonWebEncryptionAlg>,

    /// [JWE] `enc` algorithm for encrypting responses of the [introspection
    /// endpoint].
    ///
    /// If `introspection_signed_response_alg` is not provided, this field has
    /// no effect.
    ///
    /// Defaults to [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] if
    /// `introspection_encrypted_response_alg` is provided.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    /// [introspection endpoint]: https://www.rfc-editor.org/info/rfc7662
    pub introspection_encrypted_response_enc: Option<JsonWebEncryptionEnc>,

    /// `post_logout_redirect_uri` values that are pre-registered by the client
    /// for use at the provider's [RP-Initiated Logout endpoint].
    ///
    /// [RP-Initiated Logout endpoint]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
    pub post_logout_redirect_uris: Option<Vec<Url>>,
}

impl ClientMetadata {
    /// Validate this `ClientMetadata` according to the [OpenID Connect Dynamic
    /// Client Registration Spec 1.0].
    ///
    /// # Errors
    ///
    /// Will return `Err` if validation fails.
    ///
    /// [OpenID Connect Dynamic Client Registration Spec 1.0]: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
    pub fn validate(self) -> Result<VerifiedClientMetadata, ClientMetadataVerificationError> {
        let grant_types = self.grant_types();
        let has_implicit = grant_types.contains(&GrantType::Implicit);
        let has_authorization_code = grant_types.contains(&GrantType::AuthorizationCode);
        let has_both = has_implicit && has_authorization_code;

        if let Some(uris) = &self.redirect_uris {
            if let Some(uri) = uris.iter().find(|uri| uri.fragment().is_some()) {
                return Err(ClientMetadataVerificationError::RedirectUriWithFragment(
                    uri.clone(),
                ));
            }
        } else if has_authorization_code || has_implicit {
            // Required for authorization code and implicit flows
            return Err(ClientMetadataVerificationError::MissingRedirectUris);
        }

        let response_type_code = [OAuthAuthorizationEndpointResponseType::Code.into()];
        let response_types = match &self.response_types {
            Some(types) => &types[..],
            // Default to code only if the client uses the authorization code or implicit flow
            None if has_authorization_code || has_implicit => &response_type_code[..],
            None => &[],
        };

        for response_type in response_types {
            let has_code = response_type.has_code();
            let has_id_token = response_type.has_id_token();
            let has_token = response_type.has_token();
            let is_ok = has_code && has_both
                || !has_code && has_implicit
                || has_authorization_code && !has_id_token && !has_token
                || !has_code && !has_id_token && !has_token;

            if !is_ok {
                return Err(ClientMetadataVerificationError::IncoherentResponseType(
                    response_type.clone(),
                ));
            }
        }

        if self.jwks_uri.is_some() && self.jwks.is_some() {
            return Err(ClientMetadataVerificationError::JwksUriAndJwksMutuallyExclusive);
        }

        if let Some(url) = self
            .sector_identifier_uri
            .as_ref()
            .filter(|url| url.scheme() != "https")
        {
            return Err(ClientMetadataVerificationError::UrlNonHttpsScheme(
                "sector_identifier_uri",
                url.clone(),
            ));
        }

        if *self.token_endpoint_auth_method() == OAuthClientAuthenticationMethod::PrivateKeyJwt
            && self.jwks_uri.is_none()
            && self.jwks.is_none()
        {
            return Err(ClientMetadataVerificationError::MissingJwksForTokenMethod);
        }

        if let Some(alg) = &self.token_endpoint_auth_signing_alg {
            if *alg == JsonWebSignatureAlg::None {
                return Err(ClientMetadataVerificationError::UnauthorizedSigningAlgNone(
                    "token_endpoint",
                ));
            }
        } else if matches!(
            self.token_endpoint_auth_method(),
            OAuthClientAuthenticationMethod::PrivateKeyJwt
                | OAuthClientAuthenticationMethod::ClientSecretJwt
        ) {
            return Err(ClientMetadataVerificationError::MissingAuthSigningAlg(
                "token_endpoint",
            ));
        }

        if *self.id_token_signed_response_alg() == JsonWebSignatureAlg::None
            && response_types.iter().any(ResponseType::has_id_token)
        {
            return Err(ClientMetadataVerificationError::IdTokenSigningAlgNone);
        }

        if self.id_token_encrypted_response_enc.is_some() {
            self.id_token_encrypted_response_alg.as_ref().ok_or(
                ClientMetadataVerificationError::MissingEncryptionAlg("id_token"),
            )?;
        }

        if self.userinfo_encrypted_response_enc.is_some() {
            self.userinfo_encrypted_response_alg.as_ref().ok_or(
                ClientMetadataVerificationError::MissingEncryptionAlg("userinfo"),
            )?;
        }

        if self.request_object_encryption_enc.is_some() {
            self.request_object_encryption_alg.as_ref().ok_or(
                ClientMetadataVerificationError::MissingEncryptionAlg("request_object"),
            )?;
        }

        if let Some(url) = self
            .initiate_login_uri
            .as_ref()
            .filter(|url| url.scheme() != "https")
        {
            return Err(ClientMetadataVerificationError::UrlNonHttpsScheme(
                "initiate_login_uri",
                url.clone(),
            ));
        }

        if self.introspection_encrypted_response_enc.is_some() {
            self.introspection_encrypted_response_alg.as_ref().ok_or(
                ClientMetadataVerificationError::MissingEncryptionAlg("introspection"),
            )?;
        }

        Ok(VerifiedClientMetadata { inner: self })
    }

    /// Sort the properties. This is inteded to ensure a stable serialization
    /// order when needed.
    #[must_use]
    pub fn sorted(mut self) -> Self {
        // This sorts all the Vec<T> and Localized<T> fields
        if let Some(redirect_uris) = &mut self.redirect_uris {
            redirect_uris.sort();
        }
        if let Some(response_types) = &mut self.response_types {
            response_types.sort();
        }
        if let Some(grant_types) = &mut self.grant_types {
            grant_types.sort();
        }
        if let Some(contacts) = &mut self.contacts {
            contacts.sort();
        }
        if let Some(client_name) = &mut self.client_name {
            client_name.sort();
        }
        if let Some(logo_uri) = &mut self.logo_uri {
            logo_uri.sort();
        }
        if let Some(client_uri) = &mut self.client_uri {
            client_uri.sort();
        }
        if let Some(policy_uri) = &mut self.policy_uri {
            policy_uri.sort();
        }
        if let Some(tos_uri) = &mut self.tos_uri {
            tos_uri.sort();
        }
        if let Some(default_acr_values) = &mut self.default_acr_values {
            default_acr_values.sort();
        }
        if let Some(request_uris) = &mut self.request_uris {
            request_uris.sort();
        }
        if let Some(post_logout_redirect_uris) = &mut self.post_logout_redirect_uris {
            post_logout_redirect_uris.sort();
        }

        self
    }

    /// Array of the [OAuth 2.0 `response_type` values] that the client can use
    /// at the [authorization endpoint].
    ///
    /// All the types used by the client in an authorization request's
    /// `response_type` field must appear in this list.
    ///
    /// Defaults to [`DEFAULT_RESPONSE_TYPES`].
    ///
    /// [OAuth 2.0 `response_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    /// [authorization endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.1
    #[must_use]
    pub fn response_types(&self) -> Vec<ResponseType> {
        self.response_types.clone().unwrap_or_else(|| {
            DEFAULT_RESPONSE_TYPES
                .into_iter()
                .map(ResponseType::from)
                .collect()
        })
    }

    /// Array of [OAuth 2.0 `grant_type` values] that the client can use at the
    /// [token endpoint].
    ///
    /// Note that the possible grant types depend on the response types.
    ///
    /// All the types used by the client in a token request's `grant_type` field
    /// must appear in this list.
    ///
    /// Defaults to [`DEFAULT_GRANT_TYPES`].
    ///
    /// [OAuth 2.0 `grant_type` values]: https://www.rfc-editor.org/rfc/rfc7591#page-9
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    #[must_use]
    pub fn grant_types(&self) -> &[GrantType] {
        self.grant_types.as_deref().unwrap_or(DEFAULT_GRANT_TYPES)
    }

    /// The kind of the application.
    ///
    /// Defaults to [`DEFAULT_APPLICATION_TYPE`].
    #[must_use]
    pub fn application_type(&self) -> ApplicationType {
        self.application_type
            .clone()
            .unwrap_or(DEFAULT_APPLICATION_TYPE)
    }

    /// Requested client authentication method for the [token endpoint].
    ///
    /// Defaults to [`DEFAULT_TOKEN_AUTH_METHOD`].
    ///
    /// [token endpoint]: https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2
    #[must_use]
    pub fn token_endpoint_auth_method(&self) -> &OAuthClientAuthenticationMethod {
        self.token_endpoint_auth_method
            .as_ref()
            .unwrap_or(DEFAULT_TOKEN_AUTH_METHOD)
    }

    /// [JWS] `alg` algorithm required for signing the ID Token issued to this
    /// client.
    ///
    /// If this field is present, it must not be
    /// [`JsonWebSignatureAlg::None`], unless the client uses only response
    /// types that return no ID Token from the authorization endpoint.
    ///
    /// Defaults to [`DEFAULT_SIGNING_ALGORITHM`].
    ///
    /// [JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
    #[must_use]
    pub fn id_token_signed_response_alg(&self) -> &JsonWebSignatureAlg {
        self.id_token_signed_response_alg
            .as_ref()
            .unwrap_or(DEFAULT_SIGNING_ALGORITHM)
    }

    /// [JWE] `alg` and `enc` algorithms required for encrypting the ID Token
    /// issued to this client.
    ///
    /// Always returns `Some` if `id_token_encrypted_response_alg` is provided,
    /// using the default of [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] for the `enc`
    /// value if needed.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    #[must_use]
    pub fn id_token_encrypted_response(
        &self,
    ) -> Option<(&JsonWebEncryptionAlg, &JsonWebEncryptionEnc)> {
        self.id_token_encrypted_response_alg.as_ref().map(|alg| {
            (
                alg,
                self.id_token_encrypted_response_enc
                    .as_ref()
                    .unwrap_or(DEFAULT_ENCRYPTION_ENC_ALGORITHM),
            )
        })
    }

    /// [JWE] `alg` and `enc` algorithms required for encrypting user info
    /// responses.
    ///
    /// Always returns `Some` if `userinfo_encrypted_response_alg` is provided,
    /// using the default of [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] for the `enc`
    /// value if needed.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    #[must_use]
    pub fn userinfo_encrypted_response(
        &self,
    ) -> Option<(&JsonWebEncryptionAlg, &JsonWebEncryptionEnc)> {
        self.userinfo_encrypted_response_alg.as_ref().map(|alg| {
            (
                alg,
                self.userinfo_encrypted_response_enc
                    .as_ref()
                    .unwrap_or(DEFAULT_ENCRYPTION_ENC_ALGORITHM),
            )
        })
    }

    /// [JWE] `alg` and `enc` algorithms the client is declaring that it may use
    /// for encrypting Request Objects sent to the provider.
    ///
    /// Always returns `Some` if `request_object_encryption_alg` is provided,
    /// using the default of [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] for the `enc`
    /// value if needed.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    #[must_use]
    pub fn request_object_encryption(
        &self,
    ) -> Option<(&JsonWebEncryptionAlg, &JsonWebEncryptionEnc)> {
        self.request_object_encryption_alg.as_ref().map(|alg| {
            (
                alg,
                self.request_object_encryption_enc
                    .as_ref()
                    .unwrap_or(DEFAULT_ENCRYPTION_ENC_ALGORITHM),
            )
        })
    }

    /// Whether the `auth_time` Claim in the ID Token is required.
    ///
    /// Defaults to `false`.
    #[must_use]
    pub fn require_auth_time(&self) -> bool {
        self.require_auth_time.unwrap_or_default()
    }

    /// Whether the client will only send authorization requests as [Request
    /// Objects].
    ///
    /// Defaults to `false`.
    ///
    /// [Request Object]: https://www.rfc-editor.org/rfc/rfc9101.html
    #[must_use]
    pub fn require_signed_request_object(&self) -> bool {
        self.require_signed_request_object.unwrap_or_default()
    }

    /// Whether the client will only send authorization requests via the [pushed
    /// authorization request endpoint].
    ///
    /// Defaults to `false`.
    ///
    /// [pushed authorization request endpoint]: https://www.rfc-editor.org/rfc/rfc9126.html
    #[must_use]
    pub fn require_pushed_authorization_requests(&self) -> bool {
        self.require_pushed_authorization_requests
            .unwrap_or_default()
    }

    /// [JWE] `alg` and `enc` algorithms for encrypting responses of the
    /// [introspection endpoint].
    ///
    /// Always returns `Some` if `introspection_encrypted_response_alg` is
    /// provided, using the default of [`DEFAULT_ENCRYPTION_ENC_ALGORITHM`] for
    /// the `enc` value if needed.
    ///
    /// [JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
    /// [introspection endpoint]: https://www.rfc-editor.org/info/rfc7662
    #[must_use]
    pub fn introspection_encrypted_response(
        &self,
    ) -> Option<(&JsonWebEncryptionAlg, &JsonWebEncryptionEnc)> {
        self.introspection_encrypted_response_alg
            .as_ref()
            .map(|alg| {
                (
                    alg,
                    self.introspection_encrypted_response_enc
                        .as_ref()
                        .unwrap_or(DEFAULT_ENCRYPTION_ENC_ALGORITHM),
                )
            })
    }
}

/// The verified client metadata.
///
/// All the fields required by the [OpenID Connect Dynamic Client Registration
/// Spec 1.0] or with a default value are accessible via methods.
///
/// To access other fields, use this type's `Deref` implementation.
///
/// [OpenID Connect Dynamic Client Registration Spec 1.0]: https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(into = "ClientMetadataSerdeHelper")]
pub struct VerifiedClientMetadata {
    inner: ClientMetadata,
}

impl VerifiedClientMetadata {
    /// Array of redirection URIs for use in redirect-based flows such as the
    /// [authorization code flow].
    ///
    /// All the URIs used by the client in an authorization request's
    /// `redirect_uri` field must appear in this list.
    ///
    /// [authorization code flow]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
    #[must_use]
    pub fn redirect_uris(&self) -> &[Url] {
        match &self.redirect_uris {
            Some(v) => v,
            None => &[],
        }
    }
}

impl Deref for VerifiedClientMetadata {
    type Target = ClientMetadata;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// All errors that can happen when verifying [`ClientMetadata`].
#[derive(Debug, Error)]
pub enum ClientMetadataVerificationError {
    /// The redirect URIs are missing.
    #[error("redirect URIs are missing")]
    MissingRedirectUris,

    /// The redirect URI has a fragment, which is not allowed.
    #[error("redirect URI with fragment: {0}")]
    RedirectUriWithFragment(Url),

    /// The given response type is not compatible with the grant types.
    #[error("'{0}' response type not compatible with grant types")]
    IncoherentResponseType(ResponseType),

    /// Both the `jwks_uri` and `jwks` fields are present but only one is
    /// allowed.
    #[error("jwks_uri and jwks are mutually exclusive")]
    JwksUriAndJwksMutuallyExclusive,

    /// The URL of the given field doesn't use a `https` scheme.
    #[error("{0}'s URL doesn't use a https scheme: {1}")]
    UrlNonHttpsScheme(&'static str, Url),

    /// No JWK Set was provided but one is required for the token auth method.
    #[error("missing JWK Set for token auth method")]
    MissingJwksForTokenMethod,

    /// The given endpoint doesn't allow `none` as a signing algorithm.
    #[error("none signing alg unauthorized for {0}")]
    UnauthorizedSigningAlgNone(&'static str),

    /// The given endpoint is missing an auth signing algorithm, but it is
    /// required because it uses one of the `client_secret_jwt` or
    /// `private_key_jwt` authentication methods.
    #[error("{0} missing auth signing algorithm")]
    MissingAuthSigningAlg(&'static str),

    /// `none` is used as the signing algorithm for ID Tokens, but is not
    /// allowed.
    #[error("ID Token signing alg is none")]
    IdTokenSigningAlgNone,

    /// The given encryption field has an `enc` value but not `alg` value.
    #[error("{0} missing encryption alg value")]
    MissingEncryptionAlg(&'static str),
}

/// The issuer response to dynamic client registration.
#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ClientRegistrationResponse {
    /// A unique client identifier.
    pub client_id: String,

    /// A client secret, if the `token_endpoint_auth_method` requires one.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Time at which the Client Identifier was issued.
    #[serde(default)]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub client_id_issued_at: Option<DateTime<Utc>>,

    /// Time at which the client_secret will expire or 0 if it will not expire.
    ///
    /// Required if `client_secret` is issued.
    #[serde(default)]
    #[serde_as(as = "Option<TimestampSeconds<i64>>")]
    pub client_secret_expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use mas_iana::{
        jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg},
        oauth::{OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod},
    };
    use mas_jose::jwk::PublicJsonWebKeySet;
    use url::Url;

    use super::{ClientMetadata, ClientMetadataVerificationError};
    use crate::{requests::GrantType, response_type::ResponseType};

    fn valid_client_metadata() -> ClientMetadata {
        ClientMetadata {
            redirect_uris: Some(vec![Url::parse("http://localhost/oidc").unwrap()]),
            ..Default::default()
        }
    }

    fn jwks() -> PublicJsonWebKeySet {
        serde_json::from_value(serde_json::json!({
            "keys": [
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "n": "tCwhHOxX_ylh5kVwfVqW7QIBTIsPjkjCjVCppDrynuF_3msEdtEaG64eJUz84ODFNMCC0BQ57G7wrKQVWkdSDxWUEqGk2BixBiHJRWZdofz1WOBTdPVicvHW5Zl_aIt7uXWMdOp_SODw-O2y2f05EqbFWFnR2-1y9K8KbiOp82CD72ny1Jbb_3PxTs2Z0F4ECAtTzpDteaJtjeeueRjr7040JAjQ-5fpL5D1g8x14LJyVIo-FL_y94NPFbMp7UCi69CIfVHXFO8WYFz949og-47mWRrID5lS4zpx-QLuvNhUb_lSqmylUdQB3HpRdOcYdj3xwy4MHJuu7tTaf0AmCQ",
                    "use": "sig",
                    "kid": "d98f49bc6ca4581eae8dfadd494fce10ea23aab0",
                    "e": "AQAB"
                }
            ]
        })).unwrap()
    }

    #[test]
    fn validate_required_metadata() {
        let metadata = valid_client_metadata();
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_redirect_uris() {
        let mut metadata = ClientMetadata::default();

        // Err - Missing
        assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::MissingRedirectUris)
        );

        // Err - Fragment
        let wrong_uri = Url::parse("http://localhost/#fragment").unwrap();
        metadata.redirect_uris = Some(vec![
            Url::parse("http://localhost/").unwrap(),
            wrong_uri.clone(),
        ]);
        let uri = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::RedirectUriWithFragment(uri)) => uri
        );
        assert_eq!(uri, wrong_uri);

        // Ok - Path & Query
        metadata.redirect_uris = Some(vec![
            Url::parse("http://localhost/").unwrap(),
            Url::parse("http://localhost/oidc").unwrap(),
            Url::parse("http://localhost/?oidc").unwrap(),
            Url::parse("http://localhost/my-client?oidc").unwrap(),
        ]);
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_response_types() {
        let mut metadata = valid_client_metadata();

        // grant_type = authorization_code
        // code - Ok
        metadata.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::Code.into()]);
        metadata.clone().validate().unwrap();

        // code id_token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::CodeIdToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // code id_token token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // code token - Err
        let response_type: ResponseType = OAuthAuthorizationEndpointResponseType::CodeToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // id_token - Err
        let response_type: ResponseType = OAuthAuthorizationEndpointResponseType::IdToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // id_token token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::IdTokenToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::IdTokenToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // none - Ok
        metadata.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::None.into()]);
        metadata.clone().validate().unwrap();

        // grant_type = implicit
        metadata.grant_types = Some(vec![GrantType::Implicit]);
        // code - Err
        let response_type: ResponseType = OAuthAuthorizationEndpointResponseType::Code.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // code id_token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::CodeIdToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // code id_token token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // code token - Err
        let response_type: ResponseType = OAuthAuthorizationEndpointResponseType::CodeToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // id_token - Ok
        metadata.response_types =
            Some(vec![OAuthAuthorizationEndpointResponseType::IdToken.into()]);
        metadata.clone().validate().unwrap();

        // id_token token - Ok
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::IdTokenToken.into(),
        ]);
        metadata.clone().validate().unwrap();

        // token - Ok
        metadata.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::Token.into()]);
        metadata.clone().validate().unwrap();

        // none - Ok
        metadata.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::None.into()]);
        metadata.clone().validate().unwrap();

        // grant_types = [authorization_code, implicit]
        metadata.grant_types = Some(vec![GrantType::AuthorizationCode, GrantType::Implicit]);
        // code - Ok
        metadata.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::Code.into()]);
        metadata.clone().validate().unwrap();

        // code id_token - Ok
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::CodeIdToken.into(),
        ]);
        metadata.clone().validate().unwrap();

        // code id_token token - Ok
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken.into(),
        ]);
        metadata.clone().validate().unwrap();

        // code token - Ok
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::CodeToken.into(),
        ]);
        metadata.clone().validate().unwrap();

        // id_token - Ok
        metadata.response_types =
            Some(vec![OAuthAuthorizationEndpointResponseType::IdToken.into()]);
        metadata.clone().validate().unwrap();

        // id_token token - Ok
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::IdTokenToken.into(),
        ]);
        metadata.clone().validate().unwrap();

        // token - Ok
        metadata.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::Token.into()]);
        metadata.clone().validate().unwrap();

        // none - Ok
        metadata.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::None.into()]);
        metadata.clone().validate().unwrap();

        // other grant_types
        metadata.grant_types = Some(vec![GrantType::RefreshToken, GrantType::ClientCredentials]);
        // code - Err
        let response_type: ResponseType = OAuthAuthorizationEndpointResponseType::Code.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // code id_token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::CodeIdToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // code id_token token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // code token - Err
        let response_type: ResponseType = OAuthAuthorizationEndpointResponseType::CodeToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // id_token - Err
        let response_type: ResponseType = OAuthAuthorizationEndpointResponseType::IdToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // id_token token - Err
        let response_type: ResponseType =
            OAuthAuthorizationEndpointResponseType::IdTokenToken.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // token - Err
        let response_type: ResponseType = OAuthAuthorizationEndpointResponseType::Token.into();
        metadata.response_types = Some(vec![response_type.clone()]);
        let res = assert_matches!(metadata.clone().validate(), Err(ClientMetadataVerificationError::IncoherentResponseType(res)) => res);
        assert_eq!(res, response_type);

        // none - Ok
        metadata.response_types = Some(vec![OAuthAuthorizationEndpointResponseType::None.into()]);
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_jwks() {
        let mut metadata = valid_client_metadata();

        // Ok - jwks_uri is set
        metadata.jwks_uri = Some(Url::parse("http://localhost/jwks").unwrap());
        metadata.clone().validate().unwrap();

        // Err - Both are set
        metadata.jwks = Some(jwks());
        assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::JwksUriAndJwksMutuallyExclusive)
        );

        // Ok - jwks is set
        metadata.jwks_uri = None;
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_sector_identifier_uri() {
        let mut metadata = valid_client_metadata();

        // Err - Non-https URL
        let identifier_uri = Url::parse("http://localhost/").unwrap();
        metadata.sector_identifier_uri = Some(identifier_uri.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "sector_identifier_uri");
        assert_eq!(url, identifier_uri);

        // Ok - https URL
        metadata.sector_identifier_uri = Some(Url::parse("https://localhost/").unwrap());
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_token_endpoint_auth_method() {
        let mut metadata = valid_client_metadata();

        // Err - token_endpoint_auth_signing_alg is none
        metadata.token_endpoint_auth_signing_alg = Some(JsonWebSignatureAlg::None);
        let field = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::UnauthorizedSigningAlgNone(field)) => field
        );
        assert_eq!(field, "token_endpoint");

        // private_key_jwt
        metadata.token_endpoint_auth_method = Some(OAuthClientAuthenticationMethod::PrivateKeyJwt);
        metadata.token_endpoint_auth_signing_alg = Some(JsonWebSignatureAlg::Rs256);

        // Err - No JWKS
        assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::MissingJwksForTokenMethod)
        );

        // Ok - jwks_uri
        metadata.jwks_uri = Some(Url::parse("https://localhost/jwks").unwrap());
        metadata.clone().validate().unwrap();

        // Ok - jwks
        metadata.jwks_uri = None;
        metadata.jwks = Some(jwks());
        metadata.clone().validate().unwrap();

        // Err - No token_endpoint_auth_signing_alg
        metadata.token_endpoint_auth_signing_alg = None;
        let field = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::MissingAuthSigningAlg(field)) => field
        );
        assert_eq!(field, "token_endpoint");

        // client_secret_jwt
        metadata.token_endpoint_auth_method =
            Some(OAuthClientAuthenticationMethod::ClientSecretJwt);
        metadata.jwks = None;

        // Err - No token_endpoint_auth_signing_alg
        let field = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::MissingAuthSigningAlg(field)) => field
        );
        assert_eq!(field, "token_endpoint");

        // Ok - Has token_endpoint_auth_signing_alg
        metadata.token_endpoint_auth_signing_alg = Some(JsonWebSignatureAlg::Rs256);
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_id_token_signed_response_alg() {
        let mut metadata = valid_client_metadata();
        metadata.id_token_signed_response_alg = Some(JsonWebSignatureAlg::None);
        metadata.grant_types = Some(vec![GrantType::AuthorizationCode, GrantType::Implicit]);

        // Err - code id_token
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::CodeIdToken.into(),
        ]);
        assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::IdTokenSigningAlgNone)
        );

        // Err - code id_token token
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::CodeIdTokenToken.into(),
        ]);
        assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::IdTokenSigningAlgNone)
        );

        // Err - id_token
        metadata.response_types =
            Some(vec![OAuthAuthorizationEndpointResponseType::IdToken.into()]);
        assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::IdTokenSigningAlgNone)
        );

        // Err - id_token token
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::IdTokenToken.into(),
        ]);
        assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::IdTokenSigningAlgNone)
        );

        // Ok - Other response types
        metadata.response_types = Some(vec![
            OAuthAuthorizationEndpointResponseType::Code.into(),
            OAuthAuthorizationEndpointResponseType::CodeToken.into(),
            OAuthAuthorizationEndpointResponseType::Token.into(),
            OAuthAuthorizationEndpointResponseType::None.into(),
        ]);
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_id_token_encrypted_response() {
        let mut metadata = valid_client_metadata();
        metadata.id_token_encrypted_response_enc = Some(JsonWebEncryptionEnc::A128CbcHs256);

        // Err - No id_token_encrypted_response_alg
        let field = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::MissingEncryptionAlg(field)) => field
        );
        assert_eq!(field, "id_token");

        // Ok - Has id_token_encrypted_response_alg
        metadata.id_token_encrypted_response_alg = Some(JsonWebEncryptionAlg::RsaOaep);
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_userinfo_encrypted_response() {
        let mut metadata = valid_client_metadata();
        metadata.userinfo_encrypted_response_enc = Some(JsonWebEncryptionEnc::A128CbcHs256);

        // Err - No userinfo_encrypted_response_alg
        let field = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::MissingEncryptionAlg(field)) => field
        );
        assert_eq!(field, "userinfo");

        // Ok - Has userinfo_encrypted_response_alg
        metadata.userinfo_encrypted_response_alg = Some(JsonWebEncryptionAlg::RsaOaep);
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_request_object_encryption() {
        let mut metadata = valid_client_metadata();
        metadata.request_object_encryption_enc = Some(JsonWebEncryptionEnc::A128CbcHs256);

        // Err - No request_object_encryption_alg
        let field = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::MissingEncryptionAlg(field)) => field
        );
        assert_eq!(field, "request_object");

        // Ok - Has request_object_encryption_alg
        metadata.request_object_encryption_alg = Some(JsonWebEncryptionAlg::RsaOaep);
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_initiate_login_uri() {
        let mut metadata = valid_client_metadata();

        // Err - Non-https URL
        let initiate_uri = Url::parse("http://localhost/").unwrap();
        metadata.initiate_login_uri = Some(initiate_uri.clone());
        let (field, url) = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::UrlNonHttpsScheme(field, url)) => (field, url)
        );
        assert_eq!(field, "initiate_login_uri");
        assert_eq!(url, initiate_uri);

        // Ok - https URL
        metadata.initiate_login_uri = Some(Url::parse("https://localhost/").unwrap());
        metadata.validate().unwrap();
    }

    #[test]
    fn validate_introspection_encrypted_response() {
        let mut metadata = valid_client_metadata();
        metadata.introspection_encrypted_response_enc = Some(JsonWebEncryptionEnc::A128CbcHs256);

        // Err - No introspection_encrypted_response_alg
        let field = assert_matches!(
            metadata.clone().validate(),
            Err(ClientMetadataVerificationError::MissingEncryptionAlg(field)) => field
        );
        assert_eq!(field, "introspection");

        // Ok - Has introspection_encrypted_response_alg
        metadata.introspection_encrypted_response_alg = Some(JsonWebEncryptionAlg::RsaOaep);
        metadata.validate().unwrap();
    }
}
