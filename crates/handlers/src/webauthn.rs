// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Duration;
use mas_data_model::{BrowserSession, User, UserPasskey, UserPasskeyChallenge};
use mas_matrix::HomeserverConnection;
use mas_storage::{Clock, RepositoryAccess};
use rand::RngCore;
use ulid::Ulid;
use url::Url;
use webauthn_rp::{
    PublicKeyCredentialCreationOptions, RegistrationServerState,
    bin::{Decode, Encode},
    request::{
        DomainOrigin, Port, PublicKeyCredentialDescriptor, RpId, Scheme,
        register::{PublicKeyCredentialUserEntity, RegistrationVerificationOptions, UserHandle},
    },
    response::register::{error::RegCeremonyErr, ser_relaxed::RegistrationRelaxed},
};

/// User-facing errors
#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error(transparent)]
    RegistrationCeremonyError(#[from] RegCeremonyErr),

    #[error("The challenge doesn't exist, expired or doesn't belong for this session")]
    InvalidChallenge,

    #[error("Credential already exists")]
    Exists,
}

#[derive(Clone, Debug)]
pub struct Webauthn {
    rpid: Arc<RpId>,
}

impl Webauthn {
    /// Creates a new instance
    ///
    /// # Errors
    /// If the `public_base` has no valid host domain
    pub fn new(public_base: &Url) -> Result<Self> {
        let host = public_base
            .host_str()
            .context("Public base doesn't have a host")?
            .to_owned();

        let rpid = Arc::new(RpId::Domain(host.try_into()?));

        Ok(Self { rpid })
    }

    #[must_use]
    pub fn get_allowed_origin(&self) -> DomainOrigin {
        let host = (*self.rpid).as_ref();
        if host == "localhost" {
            DomainOrigin {
                scheme: Scheme::Any,
                host,
                port: Port::Any,
            }
        } else {
            DomainOrigin::new(host)
        }
    }

    /// Finds a challenge and does some checks on it
    ///
    /// # Errors
    /// [`WebauthnError::InvalidChallenge`] if the challenge is not found or is
    /// invalid.
    ///
    /// The rest of the anyhow errors should be treated as internal errors
    pub async fn lookup_challenge(
        &self,
        repo: &mut impl RepositoryAccess,
        clock: &impl Clock,
        id: Ulid,
        browser_session: Option<&BrowserSession>,
    ) -> Result<UserPasskeyChallenge> {
        let user_passkey_challenge = repo
            .user_passkey()
            .lookup_challenge(id)
            .await?
            .ok_or(WebauthnError::InvalidChallenge)?;

        // Check that challenge belongs to a browser session if provided or belongs to
        // no session if not provided. If not tied to a session, challenge should
        // be tied by a cookie and checked in the handler
        if user_passkey_challenge.user_session_id != browser_session.map(|s| s.id) {
            return Err(WebauthnError::InvalidChallenge.into());
        }

        // Challenge was already completed
        if user_passkey_challenge.completed_at.is_some() {
            return Err(WebauthnError::InvalidChallenge.into());
        }

        // Challenge has expired
        if clock.now() - user_passkey_challenge.created_at > Duration::hours(1) {
            return Err(WebauthnError::InvalidChallenge.into());
        }

        Ok(user_passkey_challenge)
    }

    /// Creates a passkey registration challenge
    ///
    /// # Returns
    /// 1. The JSON options to `navigator.credentials.create()` on the frontend
    /// 2. The created [`UserPasskeyChallenge`]
    ///
    /// # Errors
    /// Various anyhow errors that should be treated as internal errors
    pub async fn start_passkey_registration(
        &self,
        repo: &mut impl RepositoryAccess,
        rng: &mut (dyn RngCore + Send),
        clock: &impl Clock,
        conn: &impl HomeserverConnection,
        user: &User,
        browser_session: &BrowserSession,
    ) -> Result<(String, UserPasskeyChallenge)> {
        // Get display name or default to username
        let matrix_user = conn.query_user(&conn.mxid(&user.username)).await?;
        let display_name = matrix_user
            .displayname
            .unwrap_or_else(|| user.username.clone());

        // Construct the correct type of user handle...
        let user_handle = UserHandle::<[u8; 16]>::decode(user.id.to_bytes())?;
        let user_handle = UserHandle::<&[u8]>::from(&user_handle);

        let user_entity = PublicKeyCredentialUserEntity {
            name: user.username.as_str().try_into()?,
            id: user_handle,
            display_name: Some(display_name.as_str().try_into()?),
        };

        let exclude_credentials = repo
            .user_passkey()
            .all(user)
            .await?
            .into_iter()
            .map(|v| {
                Ok(PublicKeyCredentialDescriptor {
                    id: serde_json::from_str(&v.credential_id)?,
                    transports: serde_json::from_value(v.transports)?,
                })
            })
            .collect::<Result<Vec<PublicKeyCredentialDescriptor<Vec<u8>>>>>()?;

        let options = PublicKeyCredentialCreationOptions::passkey(
            &self.rpid,
            user_entity,
            exclude_credentials,
        );

        let (server_state, client_state) = options.start_ceremony()?;

        let user_passkey_challenge = repo
            .user_passkey()
            .add_challenge_for_session(rng, clock, server_state.encode()?, browser_session)
            .await?;

        Ok((
            serde_json::to_string(&client_state)?,
            user_passkey_challenge,
        ))
    }

    /// Validates and creates a passkey from a challenge response
    ///
    /// # Errors
    /// [`WebauthnError::Exists`] if the passkey credential the user is trying
    /// to register already exists.
    ///
    /// [`WebauthnError::RegistrationCeremonyError`] if the response from the
    /// user is invalid.
    ///
    /// The rest of the anyhow errors should be treated as internal errors
    pub async fn finish_passkey_registration(
        &self,
        repo: &mut impl RepositoryAccess,
        rng: &mut (dyn RngCore + Send),
        clock: &impl Clock,
        user: &User,
        user_passkey_challenge: UserPasskeyChallenge,
        response: String,
        name: String,
    ) -> Result<UserPasskey> {
        let server_state = RegistrationServerState::decode(&user_passkey_challenge.state)?;

        let response = serde_json::from_str::<RegistrationRelaxed>(&response)?.0;

        let options = RegistrationVerificationOptions::<DomainOrigin, DomainOrigin> {
            allowed_origins: &[self.get_allowed_origin()],
            client_data_json_relaxed: true,
            ..Default::default()
        };

        let user_handle = UserHandle::<[u8; 16]>::decode(user.id.to_bytes())?;
        let user_handle = UserHandle::<&[u8]>::from(&user_handle);

        let credential = server_state
            .verify(&self.rpid, user_handle, &response, &options)
            .map_err(WebauthnError::from)?;

        let cred_id = serde_json::to_string(&credential.id())?;

        // Webauthn requires that credential IDs be unique globally
        if repo.user_passkey().find(&cred_id).await?.is_some() {
            return Err(WebauthnError::Exists.into());
        };

        let user_passkey = repo
            .user_passkey()
            .add(
                rng,
                clock,
                user,
                name,
                cred_id,
                serde_json::to_value(credential.transports())?,
                credential.static_state().encode()?,
                credential.dynamic_state().encode()?.to_vec(),
                credential.metadata().encode()?,
            )
            .await?;

        repo.user_passkey()
            .complete_challenge(clock, user_passkey_challenge)
            .await?;

        Ok(user_passkey)
    }
}
