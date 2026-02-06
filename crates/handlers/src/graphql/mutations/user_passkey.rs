// Copyright 2025, 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_graphql::{Context, Description, Enum, ID, InputObject, Object};
use mas_storage::RepositoryAccess;
use ulid::Ulid;

use crate::{
    graphql::{
        model::{NodeType, UserPasskey},
        state::ContextExt,
    },
    webauthn::WebauthnError,
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

    /// The response from `navigator.credentials.create()` as a JSON string
    response: String,
}

/// The payload of the `completeRegisterPasskey` mutation
#[derive(Description)]
enum CompleteRegisterPasskeyPayload {
    Added(Box<mas_data_model::UserPasskey>),
    InvalidChallenge,
    InvalidResponse(WebauthnError),
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
            Self::Exists => CompleteRegisterPasskeyStatus::Exists,
        }
    }

    /// The passkey that was added
    async fn passkey(&self) -> Option<UserPasskey> {
        match self {
            Self::Added(passkey) => Some(UserPasskey(*passkey.clone())),
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

    /// New name for the passkey. If null, the name will be removed
    name: Option<String>,
}

/// The payload of the `renamePasskey` mutation
#[derive(Description)]
enum RenamePasskeyPayload {
    Renamed(Box<mas_data_model::UserPasskey>),
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
            Self::Renamed(passkey) => Some(UserPasskey(*passkey.clone())),
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
    Removed(Box<mas_data_model::UserPasskey>),
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
            Self::Removed(passkey) => Some(UserPasskey(*passkey.clone())),
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
        let mut repo = state.repository().await?;
        let conn = state.homeserver_connection();
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

        let webauthn = state.webauthn();

        let (options, challenge) = webauthn
            .start_passkey_registration(&mut repo, &mut rng, &clock, &conn, user, browser_session)
            .await?;

        repo.save().await?;

        Ok(StartRegisterPasskeyPayload {
            id: challenge.id,
            options,
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
        let mut repo = state.repository().await?;

        let id = NodeType::UserPasskeyChallenge.extract_ulid(&input.id)?;

        let Some(browser_session) = ctx.requester().browser_session() else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        // Allow registering passkeys if the site config allows it
        if !state.site_config().passkeys_enabled {
            return Err(async_graphql::Error::new(
                "Passkeys are not allowed on this server",
            ));
        }

        let webauthn = state.webauthn();

        let challenge = match webauthn
            .lookup_challenge(&mut repo, &clock, id, Some(browser_session))
            .await
            .map_err(anyhow::Error::downcast)
        {
            Ok(c) => c,
            Err(Ok(WebauthnError::InvalidChallenge)) => {
                return Ok(CompleteRegisterPasskeyPayload::InvalidChallenge);
            }
            Err(Ok(e)) => return Err(e.into()),
            Err(Err(e)) => return Err(e.into()),
        };

        let user_passkey = match webauthn
            .finish_passkey_registration(
                &mut repo,
                &mut rng,
                &clock,
                &browser_session.user,
                challenge,
                input.response,
            )
            .await
            .map_err(anyhow::Error::downcast)
        {
            Ok(p) => p,
            Err(Ok(WebauthnError::Exists)) => {
                return Ok(CompleteRegisterPasskeyPayload::Exists);
            }
            Err(Ok(e)) => return Ok(CompleteRegisterPasskeyPayload::InvalidResponse(e)),
            Err(Err(e)) => return Err(e.into()),
        };

        repo.save().await?;

        Ok(CompleteRegisterPasskeyPayload::Added(Box::new(
            user_passkey,
        )))
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

        if let Some(name) = &input.name
            && (name.len() > 256 || name.is_empty())
        {
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

        Ok(RenamePasskeyPayload::Renamed(Box::new(user_passkey)))
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

        Ok(RemovePasskeyPayload::Removed(Box::new(user_passkey)))
    }
}
