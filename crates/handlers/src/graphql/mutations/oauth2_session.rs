// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Description, Enum, ID, InputObject, Object};
use chrono::Duration;
use mas_data_model::{Device, TokenType};
use mas_storage::{
    RepositoryAccess,
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2ClientRepository, OAuth2RefreshTokenRepository,
        OAuth2SessionRepository,
    },
    queue::{QueueJobRepositoryExt as _, SyncDevicesJob},
    user::UserRepository,
};
use oauth2_types::scope::Scope;

use crate::graphql::{
    model::{NodeType, OAuth2Session},
    state::ContextExt,
};

#[derive(Default)]
pub struct OAuth2SessionMutations {
    _private: (),
}

/// The input of the `createOauth2Session` mutation.
#[derive(InputObject)]
pub struct CreateOAuth2SessionInput {
    /// The scope of the session
    scope: String,

    /// The ID of the user for which to create the session
    user_id: ID,

    /// Whether the session should issue a never-expiring access token
    permanent: Option<bool>,
}

/// The payload of the `createOauth2Session` mutation.
#[derive(Description)]
pub struct CreateOAuth2SessionPayload {
    access_token: String,
    refresh_token: Option<String>,
    session: mas_data_model::Session,
}

#[Object(use_type_description)]
impl CreateOAuth2SessionPayload {
    /// Access token for this session
    pub async fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Refresh token for this session, if it is not a permanent session
    pub async fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The OAuth 2.0 session which was just created
    pub async fn oauth2_session(&self) -> OAuth2Session {
        OAuth2Session(self.session.clone())
    }
}

/// The input of the `endOauth2Session` mutation.
#[derive(InputObject)]
pub struct EndOAuth2SessionInput {
    /// The ID of the session to end.
    oauth2_session_id: ID,
}

/// The payload of the `endOauth2Session` mutation.
pub enum EndOAuth2SessionPayload {
    NotFound,
    Ended(Box<mas_data_model::Session>),
}

/// The status of the `endOauth2Session` mutation.
#[derive(Enum, Copy, Clone, PartialEq, Eq, Debug)]
enum EndOAuth2SessionStatus {
    /// The session was ended.
    Ended,

    /// The session was not found.
    NotFound,
}

#[Object]
impl EndOAuth2SessionPayload {
    /// The status of the mutation.
    async fn status(&self) -> EndOAuth2SessionStatus {
        match self {
            Self::Ended(_) => EndOAuth2SessionStatus::Ended,
            Self::NotFound => EndOAuth2SessionStatus::NotFound,
        }
    }

    /// Returns the ended session.
    async fn oauth2_session(&self) -> Option<OAuth2Session> {
        match self {
            Self::Ended(session) => Some(OAuth2Session(*session.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input of the `setOauth2SessionName` mutation.
#[derive(InputObject)]
pub struct SetOAuth2SessionNameInput {
    /// The ID of the session to set the name of.
    oauth2_session_id: ID,

    /// The new name of the session.
    human_name: String,
}

/// The payload of the `setOauth2SessionName` mutation.
pub enum SetOAuth2SessionNamePayload {
    /// The session was not found.
    NotFound,

    /// The session was updated.
    Updated(Box<mas_data_model::Session>),
}

/// The status of the `setOauth2SessionName` mutation.
#[derive(Enum, Copy, Clone, PartialEq, Eq, Debug)]
enum SetOAuth2SessionNameStatus {
    /// The session was updated.
    Updated,

    /// The session was not found.
    NotFound,
}

#[Object]
impl SetOAuth2SessionNamePayload {
    /// The status of the mutation.
    async fn status(&self) -> SetOAuth2SessionNameStatus {
        match self {
            Self::Updated(_) => SetOAuth2SessionNameStatus::Updated,
            Self::NotFound => SetOAuth2SessionNameStatus::NotFound,
        }
    }

    /// The session that was updated.
    async fn oauth2_session(&self) -> Option<OAuth2Session> {
        match self {
            Self::Updated(session) => Some(OAuth2Session(*session.clone())),
            Self::NotFound => None,
        }
    }
}

#[Object]
impl OAuth2SessionMutations {
    /// Create a new arbitrary OAuth 2.0 Session.
    ///
    /// Only available for administrators.
    async fn create_oauth2_session(
        &self,
        ctx: &Context<'_>,
        input: CreateOAuth2SessionInput,
    ) -> Result<CreateOAuth2SessionPayload, async_graphql::Error> {
        let state = ctx.state();
        let homeserver = state.homeserver_connection();
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let scope: Scope = input.scope.parse().context("Invalid scope")?;
        let permanent = input.permanent.unwrap_or(false);
        let requester = ctx.requester();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let session = requester
            .oauth2_session()
            .context("Requester should be a OAuth 2.0 client")?;

        let mut repo = state.repository().await?;
        let clock = state.clock();
        let mut rng = state.rng();

        let client = repo
            .oauth2_client()
            .lookup(session.client_id)
            .await?
            .context("Client not found")?;

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        // Generate a new access token
        let access_token = TokenType::AccessToken.generate(&mut rng);

        // Create the OAuth 2.0 Session
        let session = repo
            .oauth2_session()
            .add(&mut rng, &clock, &client, Some(&user), None, scope)
            .await?;

        // Lock the user sync to make sure we don't get into a race condition
        repo.user().acquire_lock_for_sync(&user).await?;

        // Look for devices to provision
        for scope in &*session.scope {
            if let Some(device) = Device::from_scope_token(scope) {
                homeserver
                    .upsert_device(&user.username, device.as_str(), None)
                    .await
                    .context("Failed to provision device")?;
            }
        }

        let ttl = if permanent {
            None
        } else {
            Some(Duration::microseconds(5 * 60 * 1000 * 1000))
        };
        let access_token = repo
            .oauth2_access_token()
            .add(&mut rng, &clock, &session, access_token, ttl)
            .await?;

        let refresh_token = if permanent {
            None
        } else {
            let refresh_token = TokenType::RefreshToken.generate(&mut rng);

            let refresh_token = repo
                .oauth2_refresh_token()
                .add(&mut rng, &clock, &session, &access_token, refresh_token)
                .await?;

            Some(refresh_token)
        };

        repo.save().await?;

        Ok(CreateOAuth2SessionPayload {
            session,
            access_token: access_token.access_token,
            refresh_token: refresh_token.map(|t| t.refresh_token),
        })
    }

    async fn end_oauth2_session(
        &self,
        ctx: &Context<'_>,
        input: EndOAuth2SessionInput,
    ) -> Result<EndOAuth2SessionPayload, async_graphql::Error> {
        let state = ctx.state();
        let oauth2_session_id = NodeType::OAuth2Session.extract_ulid(&input.oauth2_session_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let clock = state.clock();
        let mut rng = state.rng();

        let session = repo.oauth2_session().lookup(oauth2_session_id).await?;
        let Some(session) = session else {
            return Ok(EndOAuth2SessionPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&session) {
            return Ok(EndOAuth2SessionPayload::NotFound);
        }

        if let Some(user_id) = session.user_id {
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .context("Could not load user")?;

            // Schedule a job to sync the devices of the user with the homeserver
            repo.queue_job()
                .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
                .await?;
        }

        let session = repo.oauth2_session().finish(&clock, session).await?;

        repo.save().await?;

        Ok(EndOAuth2SessionPayload::Ended(Box::new(session)))
    }

    async fn set_oauth2_session_name(
        &self,
        ctx: &Context<'_>,
        input: SetOAuth2SessionNameInput,
    ) -> Result<SetOAuth2SessionNamePayload, async_graphql::Error> {
        let state = ctx.state();
        let oauth2_session_id = NodeType::OAuth2Session.extract_ulid(&input.oauth2_session_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let homeserver = state.homeserver_connection();

        let session = repo.oauth2_session().lookup(oauth2_session_id).await?;
        let Some(session) = session else {
            return Ok(SetOAuth2SessionNamePayload::NotFound);
        };

        if !requester.is_owner_or_admin(&session) {
            return Ok(SetOAuth2SessionNamePayload::NotFound);
        }

        let user_id = session.user_id.context("Session has no user")?;

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        let session = repo
            .oauth2_session()
            .set_human_name(session, Some(input.human_name.clone()))
            .await?;

        // Update the device on the homeserver side
        for scope in &*session.scope {
            if let Some(device) = Device::from_scope_token(scope) {
                homeserver
                    .update_device_display_name(&user.username, device.as_str(), &input.human_name)
                    .await
                    .context("Failed to provision device")?;
            }
        }

        repo.save().await?;

        Ok(SetOAuth2SessionNamePayload::Updated(Box::new(session)))
    }
}
