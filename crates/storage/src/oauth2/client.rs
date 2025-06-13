// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use mas_data_model::Client;
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_jose::jwk::PublicJsonWebKeySet;
use oauth2_types::{oidc::ApplicationType, requests::GrantType};
use rand_core::RngCore;
use ulid::Ulid;
use url::Url;

use crate::{Clock, repository_impl};

/// An [`OAuth2ClientRepository`] helps interacting with [`Client`] saved in the
/// storage backend
#[async_trait]
pub trait OAuth2ClientRepository: Send + Sync {
    /// The error type returned by the repository
    type Error;

    /// Lookup an OAuth2 client by its ID
    ///
    /// Returns `None` if the client does not exist
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the client to lookup
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Client>, Self::Error>;

    /// Find an OAuth2 client by its client ID
    async fn find_by_client_id(&mut self, client_id: &str) -> Result<Option<Client>, Self::Error> {
        let Ok(id) = client_id.parse() else {
            return Ok(None);
        };
        self.lookup(id).await
    }

    /// Find an OAuth2 client by its metadata digest
    ///
    /// Returns `None` if the client does not exist
    ///
    /// # Parameters
    ///
    /// * `digest`: The metadata digest (SHA-256 hash encoded in hex) of the
    ///   client to find
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn find_by_metadata_digest(
        &mut self,
        digest: &str,
    ) -> Result<Option<Client>, Self::Error>;

    /// Load a batch of OAuth2 clients by their IDs
    ///
    /// Returns a map of client IDs to clients. If a client does not exist, it
    /// is not present in the map.
    ///
    /// # Parameters
    ///
    /// * `ids`: The IDs of the clients to load
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn load_batch(
        &mut self,
        ids: BTreeSet<Ulid>,
    ) -> Result<BTreeMap<Ulid, Client>, Self::Error>;

    /// Add a new OAuth2 client
    ///
    /// Returns the client that was added
    ///
    /// # Parameters
    ///
    /// * `rng`: The random number generator to use
    /// * `clock`: The clock used to generate timestamps
    /// * `redirect_uris`: The list of redirect URIs used by this client
    /// * `metadata_digest`: The hash of the client metadata, if computed
    /// * `encrypted_client_secret`: The encrypted client secret, if any
    /// * `application_type`: The application type of this client
    /// * `grant_types`: The list of grant types this client can use
    /// * `client_name`: The human-readable name of this client, if given
    /// * `logo_uri`: The URI of the logo of this client, if given
    /// * `client_uri`: The URI of a website of this client, if given
    /// * `policy_uri`: The URI of the privacy policy of this client, if given
    /// * `tos_uri`: The URI of the terms of service of this client, if given
    /// * `jwks_uri`: The URI of the JWKS of this client, if given
    /// * `jwks`: The JWKS of this client, if given
    /// * `id_token_signed_response_alg`: The algorithm used to sign the ID
    ///   token
    /// * `userinfo_signed_response_alg`: The algorithm used to sign the user
    ///   info. If none, the user info endpoint will not sign the response
    /// * `token_endpoint_auth_method`: The authentication method used by this
    ///   client when calling the token endpoint
    /// * `token_endpoint_auth_signing_alg`: The algorithm used to sign the JWT
    ///   when using the `client_secret_jwt` or `private_key_jwt` authentication
    ///   methods
    /// * `initiate_login_uri`: The URI used to initiate a login, if given
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    #[allow(clippy::too_many_arguments)]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        redirect_uris: Vec<Url>,
        metadata_digest: Option<String>,
        encrypted_client_secret: Option<String>,
        application_type: Option<ApplicationType>,
        grant_types: Vec<GrantType>,
        client_name: Option<String>,
        logo_uri: Option<Url>,
        client_uri: Option<Url>,
        policy_uri: Option<Url>,
        tos_uri: Option<Url>,
        jwks_uri: Option<Url>,
        jwks: Option<PublicJsonWebKeySet>,
        id_token_signed_response_alg: Option<JsonWebSignatureAlg>,
        userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
        token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,
        token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
        initiate_login_uri: Option<Url>,
    ) -> Result<Client, Self::Error>;

    /// Add or replace a static client
    ///
    /// Returns the client that was added or replaced
    ///
    /// # Parameters
    ///
    /// * `client_id`: The client ID
    /// * `client_auth_method`: The authentication method this client uses
    /// * `encrypted_client_secret`: The encrypted client secret, if any
    /// * `jwks`: The client JWKS, if any
    /// * `jwks_uri`: The client JWKS URI, if any
    /// * `redirect_uris`: The list of redirect URIs used by this client
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    #[allow(clippy::too_many_arguments)]
    async fn upsert_static(
        &mut self,
        client_id: Ulid,
        client_name: Option<String>,
        client_auth_method: OAuthClientAuthenticationMethod,
        encrypted_client_secret: Option<String>,
        jwks: Option<PublicJsonWebKeySet>,
        jwks_uri: Option<Url>,
        redirect_uris: Vec<Url>,
    ) -> Result<Client, Self::Error>;

    /// List all static clients
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn all_static(&mut self) -> Result<Vec<Client>, Self::Error>;

    /// Delete a client
    ///
    /// # Parameters
    ///
    /// * `client`: The client to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails, or if the
    /// client does not exist
    async fn delete(&mut self, client: Client) -> Result<(), Self::Error> {
        self.delete_by_id(client.id).await
    }

    /// Delete a client by ID
    ///
    /// # Parameters
    ///
    /// * `id`: The ID of the client to delete
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails, or if the
    /// client does not exist
    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error>;
}

repository_impl!(OAuth2ClientRepository:
    async fn lookup(&mut self, id: Ulid) -> Result<Option<Client>, Self::Error>;

    async fn find_by_metadata_digest(
        &mut self,
        digest: &str,
    ) -> Result<Option<Client>, Self::Error>;

    async fn load_batch(
        &mut self,
        ids: BTreeSet<Ulid>,
    ) -> Result<BTreeMap<Ulid, Client>, Self::Error>;

    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        redirect_uris: Vec<Url>,
        metadata_digest: Option<String>,
        encrypted_client_secret: Option<String>,
        application_type: Option<ApplicationType>,
        grant_types: Vec<GrantType>,
        client_name: Option<String>,
        logo_uri: Option<Url>,
        client_uri: Option<Url>,
        policy_uri: Option<Url>,
        tos_uri: Option<Url>,
        jwks_uri: Option<Url>,
        jwks: Option<PublicJsonWebKeySet>,
        id_token_signed_response_alg: Option<JsonWebSignatureAlg>,
        userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
        token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,
        token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
        initiate_login_uri: Option<Url>,
    ) -> Result<Client, Self::Error>;

    async fn upsert_static(
        &mut self,
        client_id: Ulid,
        client_name: Option<String>,
        client_auth_method: OAuthClientAuthenticationMethod,
        encrypted_client_secret: Option<String>,
        jwks: Option<PublicJsonWebKeySet>,
        jwks_uri: Option<Url>,
        redirect_uris: Vec<Url>,
    ) -> Result<Client, Self::Error>;

    async fn all_static(&mut self) -> Result<Vec<Client>, Self::Error>;

    async fn delete(&mut self, client: Client) -> Result<(), Self::Error>;

    async fn delete_by_id(&mut self, id: Ulid) -> Result<(), Self::Error>;
);
