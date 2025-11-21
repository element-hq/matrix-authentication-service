// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Description, Enum, ID, InputObject, Object};
use mas_i18n::DataLocale;
use mas_storage::{
    RepositoryAccess,
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _, SendEmailAuthenticationCodeJob},
    user::{UserEmailFilter, UserEmailRepository, UserRepository},
};

use super::verify_password_if_needed;
use crate::graphql::{
    model::{NodeType, User, UserEmail, UserEmailAuthentication},
    state::ContextExt,
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

/// The input for the `removeEmail` mutation
#[derive(InputObject)]
struct RemoveEmailInput {
    /// The ID of the email address to remove
    user_email_id: ID,

    /// The user's current password. This is required if the user is not an
    /// admin and it has a password on its account.
    password: Option<String>,
}

/// The status of the `removeEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum RemoveEmailStatus {
    /// The email address was removed
    Removed,

    /// The email address was not found
    NotFound,

    /// The password provided is incorrect
    IncorrectPassword,
}

/// The payload of the `removeEmail` mutation
#[derive(Description)]
enum RemoveEmailPayload {
    Removed(mas_data_model::UserEmail),
    NotFound,
    IncorrectPassword,
}

#[Object(use_type_description)]
impl RemoveEmailPayload {
    /// Status of the operation
    async fn status(&self) -> RemoveEmailStatus {
        match self {
            RemoveEmailPayload::Removed(_) => RemoveEmailStatus::Removed,
            RemoveEmailPayload::NotFound => RemoveEmailStatus::NotFound,
            RemoveEmailPayload::IncorrectPassword => RemoveEmailStatus::IncorrectPassword,
        }
    }

    /// The email address that was removed
    async fn email(&self) -> Option<UserEmail> {
        match self {
            RemoveEmailPayload::Removed(email) => Some(UserEmail(email.clone())),
            RemoveEmailPayload::NotFound | RemoveEmailPayload::IncorrectPassword => None,
        }
    }

    /// The user to whom the email address belonged
    async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();

        let user_id = match self {
            RemoveEmailPayload::Removed(email) => email.user_id,
            RemoveEmailPayload::NotFound | RemoveEmailPayload::IncorrectPassword => {
                return Ok(None);
            }
        };

        let mut repo = state.repository().await?;

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
}

#[Object(use_type_description)]
impl SetPrimaryEmailPayload {
    async fn status(&self) -> SetPrimaryEmailStatus {
        match self {
            SetPrimaryEmailPayload::Set(_) => SetPrimaryEmailStatus::Set,
            SetPrimaryEmailPayload::NotFound => SetPrimaryEmailStatus::NotFound,
        }
    }

    /// The user to whom the email address belongs
    async fn user(&self) -> Option<User> {
        match self {
            SetPrimaryEmailPayload::Set(user) => Some(User(user.clone())),
            SetPrimaryEmailPayload::NotFound => None,
        }
    }
}

/// The input for the `startEmailAuthentication` mutation
#[derive(InputObject)]
struct StartEmailAuthenticationInput {
    /// The email address to add to the account
    email: String,

    /// The user's current password. This is required if the user has a password
    /// on its account.
    password: Option<String>,

    /// The language to use for the email
    #[graphql(default = "en")]
    language: String,
}

/// The status of the `startEmailAuthentication` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum StartEmailAuthenticationStatus {
    /// The email address was started
    Started,
    /// The email address is invalid
    InvalidEmailAddress,
    /// Too many attempts to start an email authentication
    RateLimited,
    /// The email address isn't allowed by the policy
    Denied,
    /// The email address is already in use on this account
    InUse,
    /// The password provided is incorrect
    IncorrectPassword,
}

/// The payload of the `startEmailAuthentication` mutation
#[derive(Description)]
enum StartEmailAuthenticationPayload {
    Started(UserEmailAuthentication),
    InvalidEmailAddress,
    RateLimited,
    Denied {
        violations: Vec<mas_policy::Violation>,
    },
    InUse,
    IncorrectPassword,
}

#[Object(use_type_description)]
impl StartEmailAuthenticationPayload {
    /// Status of the operation
    async fn status(&self) -> StartEmailAuthenticationStatus {
        match self {
            Self::Started(_) => StartEmailAuthenticationStatus::Started,
            Self::InvalidEmailAddress => StartEmailAuthenticationStatus::InvalidEmailAddress,
            Self::RateLimited => StartEmailAuthenticationStatus::RateLimited,
            Self::Denied { .. } => StartEmailAuthenticationStatus::Denied,
            Self::InUse => StartEmailAuthenticationStatus::InUse,
            Self::IncorrectPassword => StartEmailAuthenticationStatus::IncorrectPassword,
        }
    }

    /// The email authentication session that was started
    async fn authentication(&self) -> Option<&UserEmailAuthentication> {
        match self {
            Self::Started(authentication) => Some(authentication),
            Self::InvalidEmailAddress
            | Self::RateLimited
            | Self::Denied { .. }
            | Self::InUse
            | Self::IncorrectPassword => None,
        }
    }

    /// The list of policy violations if the email address was denied
    async fn violations(&self) -> Option<Vec<String>> {
        let Self::Denied { violations } = self else {
            return None;
        };

        let messages = violations.iter().map(|v| v.msg.clone()).collect();
        Some(messages)
    }
}

/// The input for the `completeEmailAuthentication` mutation
#[derive(InputObject)]
struct CompleteEmailAuthenticationInput {
    /// The authentication code to use
    code: String,

    /// The ID of the authentication session to complete
    id: ID,
}

/// The payload of the `completeEmailAuthentication` mutation
#[derive(Description)]
enum CompleteEmailAuthenticationPayload {
    Completed,
    InvalidCode,
    CodeExpired,
    InUse,
    RateLimited,
}

/// The status of the `completeEmailAuthentication` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum CompleteEmailAuthenticationStatus {
    /// The authentication was completed
    Completed,
    /// The authentication code is invalid
    InvalidCode,
    /// The authentication code has expired
    CodeExpired,
    /// Too many attempts to complete an email authentication
    RateLimited,
    /// The email address is already in use
    InUse,
}

#[Object(use_type_description)]
impl CompleteEmailAuthenticationPayload {
    /// Status of the operation
    async fn status(&self) -> CompleteEmailAuthenticationStatus {
        match self {
            Self::Completed => CompleteEmailAuthenticationStatus::Completed,
            Self::InvalidCode => CompleteEmailAuthenticationStatus::InvalidCode,
            Self::CodeExpired => CompleteEmailAuthenticationStatus::CodeExpired,
            Self::InUse => CompleteEmailAuthenticationStatus::InUse,
            Self::RateLimited => CompleteEmailAuthenticationStatus::RateLimited,
        }
    }
}

/// The input for the `resendEmailAuthenticationCode` mutation
#[derive(InputObject)]
struct ResendEmailAuthenticationCodeInput {
    /// The ID of the authentication session to resend the code for
    id: ID,

    /// The language to use for the email
    #[graphql(default = "en")]
    language: String,
}

/// The payload of the `resendEmailAuthenticationCode` mutation
#[derive(Description)]
enum ResendEmailAuthenticationCodePayload {
    /// The email was resent
    Resent,
    /// The email authentication session is already completed
    Completed,
    /// Too many attempts to resend an email authentication code
    RateLimited,
}

/// The status of the `resendEmailAuthenticationCode` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum ResendEmailAuthenticationCodeStatus {
    /// The email was resent
    Resent,
    /// The email authentication session is already completed
    Completed,
    /// Too many attempts to resend an email authentication code
    RateLimited,
}

#[Object(use_type_description)]
impl ResendEmailAuthenticationCodePayload {
    /// Status of the operation
    async fn status(&self) -> ResendEmailAuthenticationCodeStatus {
        match self {
            Self::Resent => ResendEmailAuthenticationCodeStatus::Resent,
            Self::Completed => ResendEmailAuthenticationCodeStatus::Completed,
            Self::RateLimited => ResendEmailAuthenticationCodeStatus::RateLimited,
        }
    }
}

#[Object]
impl UserEmailMutations {
    /// Add an email address to the specified user
    #[graphql(deprecation = "Use `startEmailAuthentication` instead.")]
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

        // Only allow admin to call this mutation
        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let _skip_verification = input.skip_verification.unwrap_or(false);
        let skip_policy_check = input.skip_policy_check.unwrap_or(false);

        let mut repo = state.repository().await?;

        let user = repo
            .user()
            .lookup(id)
            .await?
            .context("Failed to load user")?;

        // Validate the email address
        if input.email.parse::<lettre::Address>().is_err() {
            return Ok(AddEmailPayload::Invalid);
        }

        if !skip_policy_check {
            let mut policy = state.policy().await?;
            let res = policy
                .evaluate_email(mas_policy::EmailInput {
                    email: &input.email,
                    requester: requester.for_policy(),
                })
                .await?;
            if !res.valid() {
                return Ok(AddEmailPayload::Denied {
                    violations: res.violations,
                });
            }
        }

        // Find an existing email address
        let existing_user_email = repo.user_email().find(&user, &input.email).await?;
        let (added, user_email) = if let Some(user_email) = existing_user_email {
            (false, user_email)
        } else {
            let user_email = repo
                .user_email()
                .add(&mut rng, &clock, &user, input.email)
                .await?;

            (true, user_email)
        };

        repo.save().await?;

        let payload = if added {
            AddEmailPayload::Added(user_email)
        } else {
            AddEmailPayload::Exists(user_email)
        };
        Ok(payload)
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

        // Validate the password input if needed
        if !verify_password_if_needed(
            requester,
            state.site_config(),
            &state.password_manager(),
            input.password,
            &user,
            &mut repo,
        )
        .await?
        {
            return Ok(RemoveEmailPayload::IncorrectPassword);
        }

        // TODO: don't allow removing the last email address

        repo.user_email().remove(user_email.clone()).await?;

        // Schedule a job to update the user
        repo.queue_job()
            .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
            .await?;

        repo.save().await?;

        Ok(RemoveEmailPayload::Removed(user_email))
    }

    /// Set an email address as primary
    #[graphql(
        deprecation = "This doesn't do anything anymore, but is kept to avoid breaking existing queries"
    )]
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

        // The user primary email should already be up to date
        let user = repo
            .user()
            .lookup(user_email.user_id)
            .await?
            .context("Failed to load user")?;

        repo.save().await?;

        Ok(SetPrimaryEmailPayload::Set(user))
    }

    /// Start a new email authentication flow
    async fn start_email_authentication(
        &self,
        ctx: &Context<'_>,
        input: StartEmailAuthenticationInput,
    ) -> Result<StartEmailAuthenticationPayload, async_graphql::Error> {
        let state = ctx.state();
        let mut rng = state.rng();
        let clock = state.clock();
        let requester = ctx.requester();
        let limiter = state.limiter();

        // Only allow calling this if the requester is a browser session
        let Some(browser_session) = requester.browser_session() else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        // Allow to starting the email authentication flow if the site config allows it
        if !state.site_config().email_change_allowed {
            return Err(async_graphql::Error::new(
                "Email changes are not allowed on this server",
            ));
        }

        if !state.site_config().email_change_allowed {
            return Err(async_graphql::Error::new(
                "Email authentication is not allowed on this server",
            ));
        }

        // Check if the locale is valid
        let _: DataLocale = input.language.parse()?;

        // Check if the email address is valid
        if input.email.parse::<lettre::Address>().is_err() {
            return Ok(StartEmailAuthenticationPayload::InvalidEmailAddress);
        }

        if let Err(e) =
            limiter.check_email_authentication_email(requester.fingerprint(), &input.email)
        {
            tracing::warn!(error = &e as &dyn std::error::Error);
            return Ok(StartEmailAuthenticationPayload::RateLimited);
        }

        let mut repo = state.repository().await?;

        // Check if the email address is already in use by the same user
        // We don't report here if the email address is already in use by another user,
        // because we don't want to leak information about other users. We will do that
        // only when the user enters the right verification code
        let count = repo
            .user_email()
            .count(
                UserEmailFilter::new()
                    .for_email(&input.email)
                    .for_user(&browser_session.user),
            )
            .await?;
        if count > 0 {
            return Ok(StartEmailAuthenticationPayload::InUse);
        }

        // Check if the email address is allowed by the policy
        let mut policy = state.policy().await?;
        let res = policy
            .evaluate_email(mas_policy::EmailInput {
                email: &input.email,
                requester: requester.for_policy(),
            })
            .await?;
        if !res.valid() {
            return Ok(StartEmailAuthenticationPayload::Denied {
                violations: res.violations,
            });
        }

        // Validate the password input if needed
        if !verify_password_if_needed(
            requester,
            state.site_config(),
            &state.password_manager(),
            input.password,
            &browser_session.user,
            &mut repo,
        )
        .await?
        {
            return Ok(StartEmailAuthenticationPayload::IncorrectPassword);
        }

        // Create a new authentication session
        let authentication = repo
            .user_email()
            .add_authentication_for_session(&mut rng, &clock, input.email, browser_session)
            .await?;

        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SendEmailAuthenticationCodeJob::new(&authentication, input.language),
            )
            .await?;

        repo.save().await?;

        Ok(StartEmailAuthenticationPayload::Started(
            UserEmailAuthentication(authentication),
        ))
    }

    /// Resend the email authentication code
    async fn resend_email_authentication_code(
        &self,
        ctx: &Context<'_>,
        input: ResendEmailAuthenticationCodeInput,
    ) -> Result<ResendEmailAuthenticationCodePayload, async_graphql::Error> {
        let state = ctx.state();
        let mut rng = state.rng();
        let clock = state.clock();
        let limiter = state.limiter();
        let requester = ctx.requester();

        let id = NodeType::UserEmailAuthentication.extract_ulid(&input.id)?;
        let Some(browser_session) = requester.browser_session() else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        // Allow to completing the email authentication flow if the site config allows
        // it
        if !state.site_config().email_change_allowed {
            return Err(async_graphql::Error::new(
                "Email changes are not allowed on this server",
            ));
        }

        // Check if the locale is valid
        let _: DataLocale = input.language.parse()?;

        let mut repo = state.repository().await?;

        let Some(authentication) = repo.user_email().lookup_authentication(id).await? else {
            return Ok(ResendEmailAuthenticationCodePayload::Completed);
        };

        // Make sure this authentication belongs to the requester
        if authentication.user_session_id != Some(browser_session.id) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        if authentication.completed_at.is_some() {
            return Ok(ResendEmailAuthenticationCodePayload::Completed);
        }

        if let Err(e) =
            limiter.check_email_authentication_send_code(requester.fingerprint(), &authentication)
        {
            tracing::warn!(error = &e as &dyn std::error::Error);
            return Ok(ResendEmailAuthenticationCodePayload::RateLimited);
        }

        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SendEmailAuthenticationCodeJob::new(&authentication, input.language),
            )
            .await?;

        repo.save().await?;

        Ok(ResendEmailAuthenticationCodePayload::Resent)
    }

    /// Complete the email authentication flow
    async fn complete_email_authentication(
        &self,
        ctx: &Context<'_>,
        input: CompleteEmailAuthenticationInput,
    ) -> Result<CompleteEmailAuthenticationPayload, async_graphql::Error> {
        let state = ctx.state();
        let mut rng = state.rng();
        let clock = state.clock();
        let limiter = state.limiter();

        let id = NodeType::UserEmailAuthentication.extract_ulid(&input.id)?;

        let Some(browser_session) = ctx.requester().browser_session() else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        // Allow to completing the email authentication flow if the site config allows
        // it
        if !state.site_config().email_change_allowed {
            return Err(async_graphql::Error::new(
                "Email changes are not allowed on this server",
            ));
        }

        let mut repo = state.repository().await?;

        let Some(authentication) = repo.user_email().lookup_authentication(id).await? else {
            return Ok(CompleteEmailAuthenticationPayload::InvalidCode);
        };

        // Make sure this authentication belongs to the requester
        if authentication.user_session_id != Some(browser_session.id) {
            return Ok(CompleteEmailAuthenticationPayload::InvalidCode);
        }

        if let Err(e) = limiter.check_email_authentication_attempt(&authentication) {
            tracing::warn!(error = &e as &dyn std::error::Error);
            return Ok(CompleteEmailAuthenticationPayload::RateLimited);
        }

        let Some(code) = repo
            .user_email()
            .find_authentication_code(&authentication, &input.code)
            .await?
        else {
            return Ok(CompleteEmailAuthenticationPayload::InvalidCode);
        };

        if code.expires_at < state.clock().now() {
            return Ok(CompleteEmailAuthenticationPayload::CodeExpired);
        }

        let authentication = repo
            .user_email()
            .complete_authentication_with_code(&clock, authentication, &code)
            .await?;

        // Check the email is not already in use by anyone, including the current user
        let count = repo
            .user_email()
            .count(UserEmailFilter::new().for_email(&authentication.email))
            .await?;

        if count > 0 {
            // We still want to consume the code so that it can't be reused
            repo.save().await?;

            return Ok(CompleteEmailAuthenticationPayload::InUse);
        }

        repo.user_email()
            .add(
                &mut rng,
                &clock,
                &browser_session.user,
                authentication.email,
            )
            .await?;

        repo.save().await?;

        Ok(CompleteEmailAuthenticationPayload::Completed)
    }
}
