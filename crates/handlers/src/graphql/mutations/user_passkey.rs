// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_graphql::{Context, Description, Enum, ID, InputObject, Object};
use chrono::Duration;
use mas_storage::RepositoryAccess;
use ulid::Ulid;
use webauthn_rs::prelude::{CredentialID, RegisterPublicKeyCredential, Uuid, WebauthnError};

use crate::{
    graphql::{
        model::{NodeType, UserPasskey},
        state::ContextExt,
    },
    webauthn::{ChallengeState, get_webauthn},
};

#[derive(Default)]
pub struct UserPasskeyMutations {
    _private: (),
}

/// The payload of the `startRegisterPasskey` mutation
#[derive(Description)]
struct StartRegisterPasskeyPayload {
    id: Ulid,
    options: String,
}

#[Object(use_type_description)]
impl StartRegisterPasskeyPayload {
    async fn id(&self) -> ID {
        NodeType::UserPasskeyChallenge.id(self.id)
    }

    /// The options to pass to `navigator.credentials.create()` as a JSON string
    async fn options(&self) -> &str {
        &self.options
    }
}

/// The input for the `completeRegisterPasskey` mutation
#[derive(InputObject)]
struct CompleteRegisterPasskeyInput {
    /// The ID of the passkey challenge to complete
    id: ID,

    /// Name of the passkey
    name: String,

    /// The response from `navigator.credentials.create()` as a JSON string
    response: String,
}

/// The payload of the `completeRegisterPasskey` mutation
#[derive(Description)]
enum CompleteRegisterPasskeyPayload {
    Added(mas_data_model::UserPasskey),
    InvalidChallenge,
    InvalidResponse(WebauthnError),
    InvalidName,
    Exists,
}

/// The status of the `completeRegisterPasskey` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum CompleteRegisterPasskeyStatus {
    /// The passkey was added
    Added,
    /// The challenge was invalid
    InvalidChallenge,
    /// The response was invalid
    InvalidResponse,
    /// The name for the passkey was invalid
    InvalidName,
    /// The passkey credential already exists
    Exists,
}

#[Object(use_type_description)]
impl CompleteRegisterPasskeyPayload {
    /// Status of the operation
    async fn status(&self) -> CompleteRegisterPasskeyStatus {
        match self {
            Self::Added(_) => CompleteRegisterPasskeyStatus::Added,
            Self::InvalidChallenge => CompleteRegisterPasskeyStatus::InvalidChallenge,
            Self::InvalidResponse(_) => CompleteRegisterPasskeyStatus::InvalidResponse,
            Self::InvalidName => CompleteRegisterPasskeyStatus::InvalidName,
            Self::Exists => CompleteRegisterPasskeyStatus::Exists,
        }
    }

    /// The passkey that was added
    async fn passkey(&self) -> Option<UserPasskey> {
        match self {
            Self::Added(passkey) => Some(UserPasskey(passkey.clone())),
            _ => None,
        }
    }

    /// The error when the status is `INVALID_RESPONSE`
    async fn error(&self) -> Option<String> {
        match self {
            Self::InvalidResponse(e) => Some(e.to_string()),
            _ => None,
        }
    }
}

/// The input for the `renamePasskey` mutation
#[derive(InputObject)]
struct RenamePasskeyInput {
    /// The ID of the passkey to rename
    id: ID,

    /// new name for the passkey
    name: String,
}

/// The payload of the `renamePasskey` mutation
#[derive(Description)]
enum RenamePasskeyPayload {
    Renamed(mas_data_model::UserPasskey),
    Invalid,
    NotFound,
}

/// The status of the `renamePasskey` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum RenamePasskeyStatus {
    /// The passkey was renamed
    Renamed,
    /// The new name was invalid
    Invalid,
    /// The passkey was not found
    NotFound,
}

#[Object(use_type_description)]
impl RenamePasskeyPayload {
    /// Status of the operation
    async fn status(&self) -> RenamePasskeyStatus {
        match self {
            Self::Renamed(_) => RenamePasskeyStatus::Renamed,
            Self::Invalid => RenamePasskeyStatus::Invalid,
            Self::NotFound => RenamePasskeyStatus::NotFound,
        }
    }

    /// The passkey that was renamed
    async fn passkey(&self) -> Option<UserPasskey> {
        match self {
            Self::Renamed(passkey) => Some(UserPasskey(passkey.clone())),
            _ => None,
        }
    }
}

/// The input for the `removePasskey` mutation
#[derive(InputObject)]
struct RemovePasskeyInput {
    /// The ID of the passkey to remove
    id: ID,
}

/// The payload of the `removePasskey` mutation
#[derive(Description)]
enum RemovePasskeyPayload {
    Removed(mas_data_model::UserPasskey),
    NotFound,
}

/// The status of the `removePasskey` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum RemovePasskeyStatus {
    /// The passkey was removed
    Removed,
    /// The passkey was not found
    NotFound,
}

#[Object(use_type_description)]
impl RemovePasskeyPayload {
    /// Status of the operation
    async fn status(&self) -> RemovePasskeyStatus {
        match self {
            Self::Removed(_) => RemovePasskeyStatus::Removed,
            Self::NotFound => RemovePasskeyStatus::NotFound,
        }
    }

    /// The passkey that was removed
    async fn passkey(&self) -> Option<UserPasskey> {
        match self {
            Self::Removed(passkey) => Some(UserPasskey(passkey.clone())),
            Self::NotFound => None,
        }
    }
}

#[Object]
impl UserPasskeyMutations {
    /// Start registering a new passkey
    async fn start_register_passkey(
        &self,
        ctx: &Context<'_>,
    ) -> Result<StartRegisterPasskeyPayload, async_graphql::Error> {
        let state = ctx.state();
        let mut rng = state.rng();
        let clock = state.clock();
        let requester = ctx.requester();

        // Only allow calling this if the requester is a browser session
        let Some(browser_session) = requester.browser_session() else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        let user = &browser_session.user;

        // Allow registering passkeys if the site config allows it
        if !state.site_config().passkeys_enabled {
            return Err(async_graphql::Error::new(
                "Passkeys are not allowed on this server",
            ));
        }

        let mut repo = state.repository().await?;

        let cred_ids: Vec<CredentialID> = repo
            .user_passkey()
            .all(user)
            .await?
            .into_iter()
            .map(|v| serde_json::from_str::<CredentialID>(&v.credential_id).unwrap())
            .collect();

        let conn = state.homeserver_connection();
        let matrix_user = conn.query_user(&conn.mxid(&user.username)).await?;

        let webauthn = get_webauthn(&state.site_config().public_base)?;

        let (mut challenge, state) = webauthn.start_passkey_registration(
            Uuid::from(user.id),
            &user.username,
            &matrix_user.displayname.unwrap_or(user.username.clone()),
            Some(cred_ids),
        )?;

        // Overriding odd choice in the webauthn library to set residentKey to
        // discouraged when passkeys are by definition discoverable
        if let Some(selection) = &mut challenge.public_key.authenticator_selection {
            selection.resident_key =
                Some(webauthn_rs_proto::options::ResidentKeyRequirement::Required);
            selection.require_resident_key = true;
        }

        let user_passkey_challenge = repo
            .user_passkey()
            .add_challenge_for_session(
                &mut rng,
                &clock,
                serde_json::to_value(ChallengeState::Registration(state))?,
                browser_session,
            )
            .await?;

        repo.save().await?;

        Ok(StartRegisterPasskeyPayload {
            id: user_passkey_challenge.id,
            options: serde_json::to_string(&challenge)?,
        })
    }

    /// Complete registering a new passkey
    async fn complete_register_passkey(
        &self,
        ctx: &Context<'_>,
        input: CompleteRegisterPasskeyInput,
    ) -> Result<CompleteRegisterPasskeyPayload, async_graphql::Error> {
        let state = ctx.state();
        let mut rng = state.rng();
        let clock = state.clock();

        let id = NodeType::UserPasskeyChallenge.extract_ulid(&input.id)?;

        if input.name.len() > 256 || input.name.is_empty() {
            return Ok(CompleteRegisterPasskeyPayload::InvalidName);
        }

        let Some(browser_session) = ctx.requester().browser_session() else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        // Allow registering passkeys if the site config allows it
        if !state.site_config().passkeys_enabled {
            return Err(async_graphql::Error::new(
                "Passkeys are not allowed on this server",
            ));
        }

        let mut repo = state.repository().await?;

        let Some(mut user_passkey_challenge) = repo.user_passkey().lookup_challenge(id).await?
        else {
            return Ok(CompleteRegisterPasskeyPayload::InvalidChallenge);
        };

        // Make sure this challenge belongs to the requester
        if user_passkey_challenge.user_session_id != Some(browser_session.id) {
            return Ok(CompleteRegisterPasskeyPayload::InvalidChallenge);
        }

        // Challenge was already completed
        if user_passkey_challenge.completed_at.is_some() {
            return Ok(CompleteRegisterPasskeyPayload::InvalidChallenge);
        }

        // Challenge has expired
        if clock.now() - user_passkey_challenge.created_at > Duration::hours(1) {
            return Ok(CompleteRegisterPasskeyPayload::InvalidChallenge);
        }

        let webauthn = get_webauthn(&state.site_config().public_base)?;

        let response: RegisterPublicKeyCredential = serde_json::from_str(&input.response)?;
        let ChallengeState::Registration(state) =
            serde_json::from_value(user_passkey_challenge.state.take())?
        else {
            return Ok(CompleteRegisterPasskeyPayload::InvalidChallenge);
        };

        let passkey = match webauthn.finish_passkey_registration(&response, &state) {
            Ok(p) => p,
            Err(e) => {
                return Ok(CompleteRegisterPasskeyPayload::InvalidResponse(e));
            }
        };

        let cred_id = serde_json::to_string(passkey.cred_id())?;

        // Webauthn requires that credential IDs be unique globally
        if repo.user_passkey().find(&cred_id).await?.is_some() {
            return Ok(CompleteRegisterPasskeyPayload::Exists);
        };

        let user_passkey = repo
            .user_passkey()
            .add(
                &mut rng,
                &clock,
                &browser_session.user,
                cred_id,
                input.name,
                serde_json::to_value(passkey)?,
            )
            .await?;

        repo.user_passkey()
            .complete_challenge(&clock, user_passkey_challenge)
            .await?;

        repo.save().await?;

        Ok(CompleteRegisterPasskeyPayload::Added(user_passkey))
    }

    /// Rename a passkey
    async fn rename_passkey(
        &self,
        ctx: &Context<'_>,
        input: RenamePasskeyInput,
    ) -> Result<RenamePasskeyPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();

        let id = NodeType::UserPasskey.extract_ulid(&input.id)?;

        if input.name.len() > 256 || input.name.is_empty() {
            return Ok(RenamePasskeyPayload::Invalid);
        }

        let mut repo = state.repository().await?;
        let user_passkey = repo.user_passkey().lookup(id).await?;
        let Some(user_passkey) = user_passkey else {
            return Ok(RenamePasskeyPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&user_passkey) {
            return Ok(RenamePasskeyPayload::NotFound);
        }

        // Allow non-admins to rename passkeys if the site config allows it
        if !requester.is_admin() && !state.site_config().passkeys_enabled {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let user_passkey = repo.user_passkey().rename(user_passkey, input.name).await?;

        repo.save().await?;

        Ok(RenamePasskeyPayload::Renamed(user_passkey))
    }

    /// Remove a passkey
    async fn remove_passkey(
        &self,
        ctx: &Context<'_>,
        input: RemovePasskeyInput,
    ) -> Result<RemovePasskeyPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();

        let id = NodeType::UserPasskey.extract_ulid(&input.id)?;

        let mut repo = state.repository().await?;
        let user_passkey = repo.user_passkey().lookup(id).await?;
        let Some(user_passkey) = user_passkey else {
            return Ok(RemovePasskeyPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&user_passkey) {
            return Ok(RemovePasskeyPayload::NotFound);
        }

        // Allow non-admins to remove passkeys if the site config allows it
        if !requester.is_admin() && !state.site_config().passkeys_enabled {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        repo.user_passkey().remove(user_passkey.clone()).await?;

        repo.save().await?;

        Ok(RemovePasskeyPayload::Removed(user_passkey))
    }
}
