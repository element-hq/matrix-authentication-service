// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Description, Enum, InputObject, Object, ID};
use mas_storage::{
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _, VerifyEmailJob},
    user::{UserEmailRepository, UserRepository},
    RepositoryAccess,
};

use crate::graphql::{
    model::{NodeType, User, UserEmail},
    state::ContextExt,
    UserId,
};

#[derive(Default)]
pub struct UserEmailMutations {
    _private: (),
}

/// The input for the `addEmail` mutation
#[derive(InputObject)]
struct AddEmailInput {
    /// The email address to add
    email: String,

    /// The ID of the user to add the email address to
    user_id: ID,

    /// Skip the email address verification. Only allowed for admins.
    skip_verification: Option<bool>,

    /// Skip the email address policy check. Only allowed for admins.
    skip_policy_check: Option<bool>,
}

/// The status of the `addEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum AddEmailStatus {
    /// The email address was added
    Added,
    /// The email address already exists
    Exists,
    /// The email address is invalid
    Invalid,
    /// The email address is not allowed by the policy
    Denied,
}

/// The payload of the `addEmail` mutation
#[derive(Description)]
enum AddEmailPayload {
    Added(mas_data_model::UserEmail),
    Exists(mas_data_model::UserEmail),
    Invalid,
    Denied {
        violations: Vec<mas_policy::Violation>,
    },
}

#[Object(use_type_description)]
impl AddEmailPayload {
    /// Status of the operation
    async fn status(&self) -> AddEmailStatus {
        match self {
            AddEmailPayload::Added(_) => AddEmailStatus::Added,
            AddEmailPayload::Exists(_) => AddEmailStatus::Exists,
            AddEmailPayload::Invalid => AddEmailStatus::Invalid,
            AddEmailPayload::Denied { .. } => AddEmailStatus::Denied,
        }
    }

    /// The email address that was added
    async fn email(&self) -> Option<UserEmail> {
        match self {
            AddEmailPayload::Added(email) | AddEmailPayload::Exists(email) => {
                Some(UserEmail(email.clone()))
            }
            AddEmailPayload::Invalid | AddEmailPayload::Denied { .. } => None,
        }
    }

    /// The user to whom the email address was added
    async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_id = match self {
            AddEmailPayload::Added(email) | AddEmailPayload::Exists(email) => email.user_id,
            AddEmailPayload::Invalid | AddEmailPayload::Denied { .. } => return Ok(None),
        };

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        Ok(Some(User(user)))
    }

    /// The list of policy violations if the email address was denied
    async fn violations(&self) -> Option<Vec<String>> {
        let AddEmailPayload::Denied { violations } = self else {
            return None;
        };

        let messages = violations.iter().map(|v| v.msg.clone()).collect();
        Some(messages)
    }
}

/// The input for the `sendVerificationEmail` mutation
#[derive(InputObject)]
struct SendVerificationEmailInput {
    /// The ID of the email address to verify
    user_email_id: ID,
}

/// The status of the `sendVerificationEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum SendVerificationEmailStatus {
    /// The verification email was sent
    Sent,
    /// The email address is already verified
    AlreadyVerified,
}

/// The payload of the `sendVerificationEmail` mutation
#[derive(Description)]
enum SendVerificationEmailPayload {
    Sent(mas_data_model::UserEmail),
    AlreadyVerified(mas_data_model::UserEmail),
}

#[Object(use_type_description)]
impl SendVerificationEmailPayload {
    /// Status of the operation
    async fn status(&self) -> SendVerificationEmailStatus {
        match self {
            SendVerificationEmailPayload::Sent(_) => SendVerificationEmailStatus::Sent,
            SendVerificationEmailPayload::AlreadyVerified(_) => {
                SendVerificationEmailStatus::AlreadyVerified
            }
        }
    }

    /// The email address to which the verification email was sent
    async fn email(&self) -> UserEmail {
        match self {
            SendVerificationEmailPayload::Sent(email)
            | SendVerificationEmailPayload::AlreadyVerified(email) => UserEmail(email.clone()),
        }
    }

    /// The user to whom the email address belongs
    async fn user(&self, ctx: &Context<'_>) -> Result<User, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_id = match self {
            SendVerificationEmailPayload::Sent(email)
            | SendVerificationEmailPayload::AlreadyVerified(email) => email.user_id,
        };

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        Ok(User(user))
    }
}

/// The input for the `verifyEmail` mutation
#[derive(InputObject)]
struct VerifyEmailInput {
    /// The ID of the email address to verify
    user_email_id: ID,
    /// The verification code
    code: String,
}

/// The status of the `verifyEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum VerifyEmailStatus {
    /// The email address was just verified
    Verified,
    /// The email address was already verified before
    AlreadyVerified,
    /// The verification code is invalid
    InvalidCode,
}

/// The payload of the `verifyEmail` mutation
#[derive(Description)]
enum VerifyEmailPayload {
    Verified(mas_data_model::UserEmail),
    AlreadyVerified(mas_data_model::UserEmail),
    InvalidCode,
}

#[Object(use_type_description)]
impl VerifyEmailPayload {
    /// Status of the operation
    async fn status(&self) -> VerifyEmailStatus {
        match self {
            VerifyEmailPayload::Verified(_) => VerifyEmailStatus::Verified,
            VerifyEmailPayload::AlreadyVerified(_) => VerifyEmailStatus::AlreadyVerified,
            VerifyEmailPayload::InvalidCode => VerifyEmailStatus::InvalidCode,
        }
    }

    /// The email address that was verified
    async fn email(&self) -> Option<UserEmail> {
        match self {
            VerifyEmailPayload::Verified(email) | VerifyEmailPayload::AlreadyVerified(email) => {
                Some(UserEmail(email.clone()))
            }
            VerifyEmailPayload::InvalidCode => None,
        }
    }

    /// The user to whom the email address belongs
    async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_id = match self {
            VerifyEmailPayload::Verified(email) | VerifyEmailPayload::AlreadyVerified(email) => {
                email.user_id
            }
            VerifyEmailPayload::InvalidCode => return Ok(None),
        };

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        Ok(Some(User(user)))
    }
}

/// The input for the `removeEmail` mutation
#[derive(InputObject)]
struct RemoveEmailInput {
    /// The ID of the email address to remove
    user_email_id: ID,
}

/// The status of the `removeEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum RemoveEmailStatus {
    /// The email address was removed
    Removed,

    /// Can't remove the primary email address
    Primary,

    /// The email address was not found
    NotFound,
}

/// The payload of the `removeEmail` mutation
#[derive(Description)]
enum RemoveEmailPayload {
    Removed(mas_data_model::UserEmail),
    Primary(mas_data_model::UserEmail),
    NotFound,
}

#[Object(use_type_description)]
impl RemoveEmailPayload {
    /// Status of the operation
    async fn status(&self) -> RemoveEmailStatus {
        match self {
            RemoveEmailPayload::Removed(_) => RemoveEmailStatus::Removed,
            RemoveEmailPayload::Primary(_) => RemoveEmailStatus::Primary,
            RemoveEmailPayload::NotFound => RemoveEmailStatus::NotFound,
        }
    }

    /// The email address that was removed
    async fn email(&self) -> Option<UserEmail> {
        match self {
            RemoveEmailPayload::Removed(email) | RemoveEmailPayload::Primary(email) => {
                Some(UserEmail(email.clone()))
            }
            RemoveEmailPayload::NotFound => None,
        }
    }

    /// The user to whom the email address belonged
    async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_id = match self {
            RemoveEmailPayload::Removed(email) | RemoveEmailPayload::Primary(email) => {
                email.user_id
            }
            RemoveEmailPayload::NotFound => return Ok(None),
        };

        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("User not found")?;

        Ok(Some(User(user)))
    }
}

/// The input for the `setPrimaryEmail` mutation
#[derive(InputObject)]
struct SetPrimaryEmailInput {
    /// The ID of the email address to set as primary
    user_email_id: ID,
}

/// The status of the `setPrimaryEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum SetPrimaryEmailStatus {
    /// The email address was set as primary
    Set,
    /// The email address was not found
    NotFound,
    /// Can't make an unverified email address primary
    Unverified,
}

/// The payload of the `setPrimaryEmail` mutation
#[derive(Description)]
enum SetPrimaryEmailPayload {
    Set(mas_data_model::User),
    NotFound,
    Unverified,
}

#[Object(use_type_description)]
impl SetPrimaryEmailPayload {
    async fn status(&self) -> SetPrimaryEmailStatus {
        match self {
            SetPrimaryEmailPayload::Set(_) => SetPrimaryEmailStatus::Set,
            SetPrimaryEmailPayload::NotFound => SetPrimaryEmailStatus::NotFound,
            SetPrimaryEmailPayload::Unverified => SetPrimaryEmailStatus::Unverified,
        }
    }

    /// The user to whom the email address belongs
    async fn user(&self) -> Option<User> {
        match self {
            SetPrimaryEmailPayload::Set(user) => Some(User(user.clone())),
            SetPrimaryEmailPayload::NotFound | SetPrimaryEmailPayload::Unverified => None,
        }
    }
}

#[Object]
impl UserEmailMutations {
    /// Add an email address to the specified user
    async fn add_email(
        &self,
        ctx: &Context<'_>,
        input: AddEmailInput,
    ) -> Result<AddEmailPayload, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::User.extract_ulid(&input.user_id)?;
        let requester = ctx.requester();
        let clock = state.clock();
        let mut rng = state.rng();

        if !requester.is_owner_or_admin(&UserId(id)) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        // Allow non-admins to change their email address if the site config allows it
        if !requester.is_admin() && !state.site_config().email_change_allowed {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        // Only admins can skip validation
        if (input.skip_verification.is_some() || input.skip_policy_check.is_some())
            && !requester.is_admin()
        {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let skip_verification = input.skip_verification.unwrap_or(false);
        let skip_policy_check = input.skip_policy_check.unwrap_or(false);

        let mut repo = state.repository().await?;

        let user = repo
            .user()
            .lookup(id)
            .await?
            .context("Failed to load user")?;

        // XXX: this logic should be extracted somewhere else, since most of it is
        // duplicated in mas_handlers

        // Validate the email address
        if input.email.parse::<lettre::Address>().is_err() {
            return Ok(AddEmailPayload::Invalid);
        }

        if !skip_policy_check {
            let mut policy = state.policy().await?;
            let res = policy.evaluate_email(&input.email).await?;
            if !res.valid() {
                return Ok(AddEmailPayload::Denied {
                    violations: res.violations,
                });
            }
        }

        // Find an existing email address
        let existing_user_email = repo.user_email().find(&user, &input.email).await?;
        let (added, mut user_email) = if let Some(user_email) = existing_user_email {
            (false, user_email)
        } else {
            let user_email = repo
                .user_email()
                .add(&mut rng, &clock, &user, input.email)
                .await?;

            (true, user_email)
        };

        // Schedule a job to verify the email address if needed
        if user_email.confirmed_at.is_none() {
            if skip_verification {
                user_email = repo
                    .user_email()
                    .mark_as_verified(&state.clock(), user_email)
                    .await?;
            } else {
                // TODO: figure out the locale
                repo.queue_job()
                    .schedule_job(&mut rng, &clock, VerifyEmailJob::new(&user_email))
                    .await?;
            }
        }

        repo.save().await?;

        let payload = if added {
            AddEmailPayload::Added(user_email)
        } else {
            AddEmailPayload::Exists(user_email)
        };
        Ok(payload)
    }

    /// Send a verification code for an email address
    async fn send_verification_email(
        &self,
        ctx: &Context<'_>,
        input: SendVerificationEmailInput,
    ) -> Result<SendVerificationEmailPayload, async_graphql::Error> {
        let state = ctx.state();
        let clock = state.clock();
        let mut rng = state.rng();
        let user_email_id = NodeType::UserEmail.extract_ulid(&input.user_email_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;

        let user_email = repo
            .user_email()
            .lookup(user_email_id)
            .await?
            .context("User email not found")?;

        if !requester.is_owner_or_admin(&user_email) {
            return Err(async_graphql::Error::new("User email not found"));
        }

        // Schedule a job to verify the email address if needed
        let needs_verification = user_email.confirmed_at.is_none();
        if needs_verification {
            // TODO: figure out the locale
            repo.queue_job()
                .schedule_job(&mut rng, &clock, VerifyEmailJob::new(&user_email))
                .await?;
        }

        repo.save().await?;

        let payload = if needs_verification {
            SendVerificationEmailPayload::Sent(user_email)
        } else {
            SendVerificationEmailPayload::AlreadyVerified(user_email)
        };
        Ok(payload)
    }

    /// Submit a verification code for an email address
    async fn verify_email(
        &self,
        ctx: &Context<'_>,
        input: VerifyEmailInput,
    ) -> Result<VerifyEmailPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_email_id = NodeType::UserEmail.extract_ulid(&input.user_email_id)?;
        let requester = ctx.requester();

        let clock = state.clock();
        let mut rng = state.rng();
        let mut repo = state.repository().await?;

        let user_email = repo
            .user_email()
            .lookup(user_email_id)
            .await?
            .context("User email not found")?;

        if !requester.is_owner_or_admin(&user_email) {
            return Err(async_graphql::Error::new("User email not found"));
        }

        if user_email.confirmed_at.is_some() {
            // Just return the email address if it's already verified
            // XXX: should we return an error instead?
            return Ok(VerifyEmailPayload::AlreadyVerified(user_email));
        }

        // XXX: this logic should be extracted somewhere else, since most of it is
        // duplicated in mas_handlers

        // Find the verification code
        let verification = repo
            .user_email()
            .find_verification_code(&clock, &user_email, &input.code)
            .await?
            .filter(|v| v.is_valid());

        let Some(verification) = verification else {
            return Ok(VerifyEmailPayload::InvalidCode);
        };

        repo.user_email()
            .consume_verification_code(&clock, verification)
            .await?;

        let user = repo
            .user()
            .lookup(user_email.user_id)
            .await?
            .context("Failed to load user")?;

        // XXX: is this the right place to do this?
        if user.primary_user_email_id.is_none() {
            repo.user_email().set_as_primary(&user_email).await?;
        }

        let user_email = repo
            .user_email()
            .mark_as_verified(&clock, user_email)
            .await?;

        repo.queue_job()
            .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
            .await?;

        repo.save().await?;

        Ok(VerifyEmailPayload::Verified(user_email))
    }

    /// Remove an email address
    async fn remove_email(
        &self,
        ctx: &Context<'_>,
        input: RemoveEmailInput,
    ) -> Result<RemoveEmailPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_email_id = NodeType::UserEmail.extract_ulid(&input.user_email_id)?;
        let requester = ctx.requester();

        let mut rng = state.rng();
        let clock = state.clock();
        let mut repo = state.repository().await?;

        let user_email = repo.user_email().lookup(user_email_id).await?;
        let Some(user_email) = user_email else {
            return Ok(RemoveEmailPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&user_email) {
            return Ok(RemoveEmailPayload::NotFound);
        }

        // Allow non-admins to remove their email address if the site config allows it
        if !requester.is_admin() && !state.site_config().email_change_allowed {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let user = repo
            .user()
            .lookup(user_email.user_id)
            .await?
            .context("Failed to load user")?;

        if user.primary_user_email_id == Some(user_email.id) {
            // Prevent removing the primary email address
            return Ok(RemoveEmailPayload::Primary(user_email));
        }

        repo.user_email().remove(user_email.clone()).await?;

        // Schedule a job to update the user
        repo.queue_job()
            .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
            .await?;

        repo.save().await?;

        Ok(RemoveEmailPayload::Removed(user_email))
    }

    /// Set an email address as primary
    async fn set_primary_email(
        &self,
        ctx: &Context<'_>,
        input: SetPrimaryEmailInput,
    ) -> Result<SetPrimaryEmailPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_email_id = NodeType::UserEmail.extract_ulid(&input.user_email_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;

        let user_email = repo.user_email().lookup(user_email_id).await?;
        let Some(user_email) = user_email else {
            return Ok(SetPrimaryEmailPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&user_email) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        // Allow non-admins to change their primary email address if the site config
        // allows it
        if !requester.is_admin() && !state.site_config().email_change_allowed {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        if user_email.confirmed_at.is_none() {
            return Ok(SetPrimaryEmailPayload::Unverified);
        }

        repo.user_email().set_as_primary(&user_email).await?;

        // The user primary email should already be up to date
        let user = repo
            .user()
            .lookup(user_email.user_id)
            .await?
            .context("Failed to load user")?;

        repo.save().await?;

        Ok(SetPrimaryEmailPayload::Set(user))
    }
}
