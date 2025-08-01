// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Description, Enum, ID, InputObject, Object};
use mas_storage::{
    queue::{
        DeactivateUserJob, ProvisionUserJob, QueueJobRepositoryExt as _,
        SendAccountRecoveryEmailsJob,
    },
    user::UserRepository,
};
use tracing::{info, warn};
use ulid::Ulid;
use url::Url;
use zeroize::Zeroizing;

use super::verify_password_if_needed;
use crate::graphql::{
    UserId,
    model::{NodeType, User},
    state::ContextExt,
};

#[derive(Default)]
pub struct UserMutations {
    _private: (),
}

/// The input for the `addUser` mutation.
#[derive(InputObject)]
struct AddUserInput {
    /// The username of the user to add.
    username: String,

    /// Skip checking with the homeserver whether the username is valid.
    ///
    /// Use this with caution! The main reason to use this, is when a user used
    /// by an application service needs to exist in MAS to craft special
    /// tokens (like with admin access) for them
    skip_homeserver_check: Option<bool>,
}

/// The status of the `addUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum AddUserStatus {
    /// The user was added.
    Added,

    /// The user already exists.
    Exists,

    /// The username is reserved.
    Reserved,

    /// The username is invalid.
    Invalid,
}

/// The payload for the `addUser` mutation.
#[derive(Description)]
enum AddUserPayload {
    Added(mas_data_model::User),
    Exists(mas_data_model::User),
    Reserved,
    Invalid,
}

#[Object(use_type_description)]
impl AddUserPayload {
    /// Status of the operation
    async fn status(&self) -> AddUserStatus {
        match self {
            Self::Added(_) => AddUserStatus::Added,
            Self::Exists(_) => AddUserStatus::Exists,
            Self::Reserved => AddUserStatus::Reserved,
            Self::Invalid => AddUserStatus::Invalid,
        }
    }

    /// The user that was added.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Added(user) | Self::Exists(user) => Some(User(user.clone())),
            Self::Invalid | Self::Reserved => None,
        }
    }
}

/// The input for the `lockUser` mutation.
#[derive(InputObject)]
struct LockUserInput {
    /// The ID of the user to lock.
    user_id: ID,

    /// Permanently lock the user.
    deactivate: Option<bool>,
}

/// The status of the `lockUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum LockUserStatus {
    /// The user was locked.
    Locked,

    /// The user was not found.
    NotFound,
}

/// The payload for the `lockUser` mutation.
#[derive(Description)]
enum LockUserPayload {
    /// The user was locked.
    Locked(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl LockUserPayload {
    /// Status of the operation
    async fn status(&self) -> LockUserStatus {
        match self {
            Self::Locked(_) => LockUserStatus::Locked,
            Self::NotFound => LockUserStatus::NotFound,
        }
    }

    /// The user that was locked.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Locked(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `unlockUser` mutation.
#[derive(InputObject)]
struct UnlockUserInput {
    /// The ID of the user to unlock
    user_id: ID,
}

/// The status of the `unlockUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum UnlockUserStatus {
    /// The user was unlocked.
    Unlocked,

    /// The user was not found.
    NotFound,
}

/// The payload for the `unlockUser` mutation.
#[derive(Description)]
enum UnlockUserPayload {
    /// The user was unlocked.
    Unlocked(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl UnlockUserPayload {
    /// Status of the operation
    async fn status(&self) -> UnlockUserStatus {
        match self {
            Self::Unlocked(_) => UnlockUserStatus::Unlocked,
            Self::NotFound => UnlockUserStatus::NotFound,
        }
    }

    /// The user that was unlocked.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Unlocked(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `setCanRequestAdmin` mutation.
#[derive(InputObject)]
struct SetCanRequestAdminInput {
    /// The ID of the user to update.
    user_id: ID,

    /// Whether the user can request admin.
    can_request_admin: bool,
}

/// The payload for the `setCanRequestAdmin` mutation.
#[derive(Description)]
enum SetCanRequestAdminPayload {
    /// The user was updated.
    Updated(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl SetCanRequestAdminPayload {
    /// The user that was updated.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Updated(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `allowUserCrossSigningReset` mutation.
#[derive(InputObject)]
struct AllowUserCrossSigningResetInput {
    /// The ID of the user to update.
    user_id: ID,
}

/// The payload for the `allowUserCrossSigningReset` mutation.
#[derive(Description)]
enum AllowUserCrossSigningResetPayload {
    /// The user was updated.
    Allowed(mas_data_model::User),

    /// The user was not found.
    NotFound,
}

#[Object(use_type_description)]
impl AllowUserCrossSigningResetPayload {
    /// The user that was updated.
    async fn user(&self) -> Option<User> {
        match self {
            Self::Allowed(user) => Some(User(user.clone())),
            Self::NotFound => None,
        }
    }
}

/// The input for the `setPassword` mutation.
#[derive(InputObject)]
struct SetPasswordInput {
    /// The ID of the user to set the password for.
    /// If you are not a server administrator then this must be your own user
    /// ID.
    user_id: ID,

    /// The current password of the user.
    /// Required if you are not a server administrator.
    current_password: Option<String>,

    /// The new password for the user.
    new_password: String,
}

/// The input for the `setPasswordByRecovery` mutation.
#[derive(InputObject)]
struct SetPasswordByRecoveryInput {
    /// The recovery ticket to use.
    /// This identifies the user as well as proving authorisation to perform the
    /// recovery operation.
    ticket: String,

    /// The new password for the user.
    new_password: String,
}

/// The return type for the `setPassword` mutation.
#[derive(Description)]
struct SetPasswordPayload {
    status: SetPasswordStatus,
}

/// The status of the `setPassword` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum SetPasswordStatus {
    /// The password was updated.
    Allowed,

    /// The user was not found.
    NotFound,

    /// The user doesn't have a current password to attempt to match against.
    NoCurrentPassword,

    /// The supplied current password was wrong.
    WrongPassword,

    /// The new password is invalid. For example, it may not meet configured
    /// security requirements.
    InvalidNewPassword,

    /// You aren't allowed to set the password for that user.
    /// This happens if you aren't setting your own password and you aren't a
    /// server administrator.
    NotAllowed,

    /// Password support has been disabled.
    /// This usually means that login is handled by an upstream identity
    /// provider.
    PasswordChangesDisabled,

    /// The specified recovery ticket does not exist.
    NoSuchRecoveryTicket,

    /// The specified recovery ticket has already been used and cannot be used
    /// again.
    RecoveryTicketAlreadyUsed,

    /// The specified recovery ticket has expired.
    ExpiredRecoveryTicket,

    /// Your account is locked and you can't change its password.
    AccountLocked,
}

#[Object(use_type_description)]
impl SetPasswordPayload {
    /// Status of the operation
    async fn status(&self) -> SetPasswordStatus {
        self.status
    }
}

/// The input for the `resendRecoveryEmail` mutation.
#[derive(InputObject)]
pub struct ResendRecoveryEmailInput {
    /// The recovery ticket to use.
    ticket: String,
}

/// The return type for the `resendRecoveryEmail` mutation.
#[derive(Description)]
pub enum ResendRecoveryEmailPayload {
    NoSuchRecoveryTicket,
    RateLimited,
    Sent { recovery_session_id: Ulid },
}

/// The status of the `resendRecoveryEmail` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum ResendRecoveryEmailStatus {
    /// The recovery ticket was not found.
    NoSuchRecoveryTicket,

    /// The rate limit was exceeded.
    RateLimited,

    /// The recovery email was sent.
    Sent,
}

#[Object(use_type_description)]
impl ResendRecoveryEmailPayload {
    /// Status of the operation
    async fn status(&self) -> ResendRecoveryEmailStatus {
        match self {
            Self::NoSuchRecoveryTicket => ResendRecoveryEmailStatus::NoSuchRecoveryTicket,
            Self::RateLimited => ResendRecoveryEmailStatus::RateLimited,
            Self::Sent { .. } => ResendRecoveryEmailStatus::Sent,
        }
    }

    /// URL to continue the recovery process
    async fn progress_url(&self, context: &Context<'_>) -> Option<Url> {
        let state = context.state();
        let url_builder = state.url_builder();
        match self {
            Self::NoSuchRecoveryTicket | Self::RateLimited => None,
            Self::Sent {
                recovery_session_id,
            } => {
                let route = mas_router::AccountRecoveryProgress::new(*recovery_session_id);
                Some(url_builder.absolute_url_for(&route))
            }
        }
    }
}

/// The input for the `deactivateUser` mutation.
#[derive(InputObject)]
pub struct DeactivateUserInput {
    /// Whether to ask the homeserver to GDPR-erase the user
    ///
    /// This is equivalent to the `erase` parameter on the
    /// `/_matrix/client/v3/account/deactivate` C-S API, which is
    /// implementation-specific.
    ///
    /// What Synapse does is documented here:
    /// <https://element-hq.github.io/synapse/latest/admin_api/user_admin_api.html#deactivate-account>
    hs_erase: bool,

    /// The password of the user to deactivate.
    password: Option<String>,
}

/// The payload for the `deactivateUser` mutation.
#[derive(Description)]
pub enum DeactivateUserPayload {
    /// The user was deactivated.
    Deactivated(mas_data_model::User),

    /// The password was wrong or missing.
    IncorrectPassword,
}

/// The status of the `deactivateUser` mutation.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum DeactivateUserStatus {
    /// The user was deactivated.
    Deactivated,

    /// The password was wrong.
    IncorrectPassword,
}

#[Object(use_type_description)]
impl DeactivateUserPayload {
    /// Status of the operation
    async fn status(&self) -> DeactivateUserStatus {
        match self {
            Self::Deactivated(_) => DeactivateUserStatus::Deactivated,
            Self::IncorrectPassword => DeactivateUserStatus::IncorrectPassword,
        }
    }

    async fn user(&self) -> Option<User> {
        match self {
            Self::Deactivated(user) => Some(User(user.clone())),
            Self::IncorrectPassword => None,
        }
    }
}

fn valid_username_character(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_digit()
        || c == '='
        || c == '_'
        || c == '-'
        || c == '.'
        || c == '/'
        || c == '+'
}

// XXX: this should probably be moved somewhere else
fn username_valid(username: &str) -> bool {
    if username.is_empty() || username.len() > 255 {
        return false;
    }

    // Should not start with an underscore
    if username.starts_with('_') {
        return false;
    }

    // Should only contain valid characters
    if !username.chars().all(valid_username_character) {
        return false;
    }

    true
}

#[Object]
impl UserMutations {
    /// Add a user. This is only available to administrators.
    async fn add_user(
        &self,
        ctx: &Context<'_>,
        input: AddUserInput,
    ) -> Result<AddUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let clock = state.clock();
        let mut rng = state.rng();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        if let Some(user) = repo.user().find_by_username(&input.username).await? {
            return Ok(AddUserPayload::Exists(user));
        }

        // Do some basic check on the username
        if !username_valid(&input.username) {
            return Ok(AddUserPayload::Invalid);
        }

        // Ask the homeserver if the username is available
        let homeserver_available = state
            .homeserver_connection()
            .is_localpart_available(&input.username)
            .await?;

        if !homeserver_available {
            if !input.skip_homeserver_check.unwrap_or(false) {
                return Ok(AddUserPayload::Reserved);
            }

            // If we skipped the check, we still want to shout about it
            warn!("Skipped homeserver check for username {}", input.username);
        }

        let user = repo.user().add(&mut rng, &clock, input.username).await?;

        repo.queue_job()
            .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&user))
            .await?;

        repo.save().await?;

        Ok(AddUserPayload::Added(user))
    }

    /// Lock a user. This is only available to administrators.
    async fn lock_user(
        &self,
        ctx: &Context<'_>,
        input: LockUserInput,
    ) -> Result<LockUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let clock = state.clock();
        let mut rng = state.rng();
        let requester = ctx.requester();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let user = repo.user().lookup(user_id).await?;

        let Some(user) = user else {
            return Ok(LockUserPayload::NotFound);
        };

        let deactivate = input.deactivate.unwrap_or(false);

        let user = repo.user().lock(&state.clock(), user).await?;

        if deactivate {
            info!(%user.id, "Scheduling deactivation of user");
            repo.queue_job()
                .schedule_job(&mut rng, &clock, DeactivateUserJob::new(&user, deactivate))
                .await?;
        }

        repo.save().await?;

        Ok(LockUserPayload::Locked(user))
    }

    /// Unlock and reactivate a user. This is only available to administrators.
    async fn unlock_user(
        &self,
        ctx: &Context<'_>,
        input: UnlockUserInput,
    ) -> Result<UnlockUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let matrix = state.homeserver_connection();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let user = repo.user().lookup(user_id).await?;

        let Some(user) = user else {
            return Ok(UnlockUserPayload::NotFound);
        };

        // Call the homeserver synchronously to reactivate the user
        matrix.reactivate_user(&user.username).await?;

        // Now reactivate & unlock the user in our database
        let user = repo.user().reactivate(user).await?;
        let user = repo.user().unlock(user).await?;

        repo.save().await?;

        Ok(UnlockUserPayload::Unlocked(user))
    }

    /// Set whether a user can request admin. This is only available to
    /// administrators.
    async fn set_can_request_admin(
        &self,
        ctx: &Context<'_>,
        input: SetCanRequestAdminInput,
    ) -> Result<SetCanRequestAdminPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();

        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;

        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let user = repo.user().lookup(user_id).await?;

        let Some(user) = user else {
            return Ok(SetCanRequestAdminPayload::NotFound);
        };

        let user = repo
            .user()
            .set_can_request_admin(user, input.can_request_admin)
            .await?;

        repo.save().await?;

        Ok(SetCanRequestAdminPayload::Updated(user))
    }

    /// Temporarily allow user to reset their cross-signing keys.
    async fn allow_user_cross_signing_reset(
        &self,
        ctx: &Context<'_>,
        input: AllowUserCrossSigningResetInput,
    ) -> Result<AllowUserCrossSigningResetPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let requester = ctx.requester();

        if !requester.is_owner_or_admin(&UserId(user_id)) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;
        let user = repo.user().lookup(user_id).await?;
        repo.cancel().await?;

        let Some(user) = user else {
            return Ok(AllowUserCrossSigningResetPayload::NotFound);
        };

        let conn = state.homeserver_connection();
        conn.allow_cross_signing_reset(&user.username)
            .await
            .context("Failed to allow cross-signing reset")?;

        Ok(AllowUserCrossSigningResetPayload::Allowed(user))
    }

    /// Set the password for a user.
    ///
    /// This can be used by server administrators to set any user's password,
    /// or, provided the capability hasn't been disabled on this server,
    /// by a user to change their own password as long as they know their
    /// current password.
    async fn set_password(
        &self,
        ctx: &Context<'_>,
        input: SetPasswordInput,
    ) -> Result<SetPasswordPayload, async_graphql::Error> {
        let state = ctx.state();
        let user_id = NodeType::User.extract_ulid(&input.user_id)?;
        let requester = ctx.requester();

        if !requester.is_owner_or_admin(&UserId(user_id)) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        if input.new_password.is_empty() {
            // TODO Expose the reason for the policy violation
            // This involves redesigning the error handling
            // Idea would be to expose an errors array in the response,
            // with a list of union of different error kinds.
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::InvalidNewPassword,
            });
        }

        let password_manager = state.password_manager();

        if !password_manager.is_enabled() {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::PasswordChangesDisabled,
            });
        }

        if !password_manager.is_password_complex_enough(&input.new_password)? {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::InvalidNewPassword,
            });
        }

        let mut repo = state.repository().await?;
        let Some(user) = repo.user().lookup(user_id).await? else {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::NotFound,
            });
        };

        if !requester.is_admin() {
            // If the user isn't an admin, we:
            // - check that password changes are enabled
            // - check that they know their current password

            if !state.site_config().password_change_allowed {
                return Ok(SetPasswordPayload {
                    status: SetPasswordStatus::PasswordChangesDisabled,
                });
            }

            let Some(active_password) = repo.user_password().active(&user).await? else {
                // The user has no current password, so can't verify against one.
                // In the future, it may be desirable to let the user set a password without any
                // other verification instead.

                return Ok(SetPasswordPayload {
                    status: SetPasswordStatus::NoCurrentPassword,
                });
            };

            let Some(current_password_attempt) = input.current_password else {
                return Err(async_graphql::Error::new(
                    "You must supply `currentPassword` to change your own password if you are not an administrator",
                ));
            };

            if let Err(_err) = password_manager
                .verify(
                    active_password.version,
                    Zeroizing::new(current_password_attempt),
                    active_password.hashed_password,
                )
                .await
            {
                return Ok(SetPasswordPayload {
                    status: SetPasswordStatus::WrongPassword,
                });
            }
        }

        let (new_password_version, new_password_hash) = password_manager
            .hash(state.rng(), Zeroizing::new(input.new_password))
            .await?;

        repo.user_password()
            .add(
                &mut state.rng(),
                &state.clock(),
                &user,
                new_password_version,
                new_password_hash,
                None,
            )
            .await?;

        repo.save().await?;

        Ok(SetPasswordPayload {
            status: SetPasswordStatus::Allowed,
        })
    }

    /// Set the password for yourself, using a recovery ticket sent by e-mail.
    async fn set_password_by_recovery(
        &self,
        ctx: &Context<'_>,
        input: SetPasswordByRecoveryInput,
    ) -> Result<SetPasswordPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let clock = state.clock();
        if !requester.is_unauthenticated() {
            return Err(async_graphql::Error::new(
                "Account recovery is only for anonymous users.",
            ));
        }

        let password_manager = state.password_manager();

        if !password_manager.is_enabled() || !state.site_config().account_recovery_allowed {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::PasswordChangesDisabled,
            });
        }

        if !password_manager.is_password_complex_enough(&input.new_password)? {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::InvalidNewPassword,
            });
        }

        let mut repo = state.repository().await?;

        let Some(ticket) = repo.user_recovery().find_ticket(&input.ticket).await? else {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::NoSuchRecoveryTicket,
            });
        };

        let session = repo
            .user_recovery()
            .lookup_session(ticket.user_recovery_session_id)
            .await?
            .context("Unknown session")?;

        if session.consumed_at.is_some() {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::RecoveryTicketAlreadyUsed,
            });
        }

        if !ticket.active(clock.now()) {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::ExpiredRecoveryTicket,
            });
        }

        let user_email = repo
            .user_email()
            .lookup(ticket.user_email_id)
            .await?
            .context("Unknown email address")?;

        let user = repo
            .user()
            .lookup(user_email.user_id)
            .await?
            .context("Invalid user")?;

        if !user.is_valid() {
            return Ok(SetPasswordPayload {
                status: SetPasswordStatus::AccountLocked,
            });
        }

        let (new_password_version, new_password_hash) = password_manager
            .hash(state.rng(), Zeroizing::new(input.new_password))
            .await?;

        repo.user_password()
            .add(
                &mut state.rng(),
                &state.clock(),
                &user,
                new_password_version,
                new_password_hash,
                None,
            )
            .await?;

        // Mark the session as consumed
        repo.user_recovery()
            .consume_ticket(&clock, ticket, session)
            .await?;

        repo.save().await?;

        Ok(SetPasswordPayload {
            status: SetPasswordStatus::Allowed,
        })
    }

    /// Resend a user recovery email
    ///
    /// This is used when a user opens a recovery link that has expired. In this
    /// case, we display a link for them to get a new recovery email, which
    /// calls this mutation.
    pub async fn resend_recovery_email(
        &self,
        ctx: &Context<'_>,
        input: ResendRecoveryEmailInput,
    ) -> Result<ResendRecoveryEmailPayload, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let clock = state.clock();
        let mut rng = state.rng();
        let limiter = state.limiter();
        let mut repo = state.repository().await?;

        let Some(recovery_ticket) = repo.user_recovery().find_ticket(&input.ticket).await? else {
            return Ok(ResendRecoveryEmailPayload::NoSuchRecoveryTicket);
        };

        let recovery_session = repo
            .user_recovery()
            .lookup_session(recovery_ticket.user_recovery_session_id)
            .await?
            .context("Could not load recovery session")?;

        if let Err(e) =
            limiter.check_account_recovery(requester.fingerprint(), &recovery_session.email)
        {
            tracing::warn!(error = &e as &dyn std::error::Error);
            return Ok(ResendRecoveryEmailPayload::RateLimited);
        }

        // Schedule a new batch of emails
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                SendAccountRecoveryEmailsJob::new(&recovery_session),
            )
            .await?;

        repo.save().await?;

        Ok(ResendRecoveryEmailPayload::Sent {
            recovery_session_id: recovery_session.id,
        })
    }

    /// Deactivate the current user account
    ///
    /// If the user has a password, it *must* be supplied in the `password`
    /// field.
    async fn deactivate_user(
        &self,
        ctx: &Context<'_>,
        input: DeactivateUserInput,
    ) -> Result<DeactivateUserPayload, async_graphql::Error> {
        let state = ctx.state();
        let mut rng = state.rng();
        let clock = state.clock();
        let requester = ctx.requester();
        let site_config = state.site_config();

        // Only allow calling this if the requester is a browser session
        let Some(browser_session) = requester.browser_session() else {
            return Err(async_graphql::Error::new("Unauthorized"));
        };

        if !site_config.account_deactivation_allowed {
            return Err(async_graphql::Error::new(
                "Account deactivation is not allowed on this server",
            ));
        }

        let mut repo = state.repository().await?;
        if !verify_password_if_needed(
            requester,
            site_config,
            &state.password_manager(),
            input.password,
            &browser_session.user,
            &mut repo,
        )
        .await?
        {
            return Ok(DeactivateUserPayload::IncorrectPassword);
        }

        // Deactivate the user right away
        let user = repo
            .user()
            .deactivate(&state.clock(), browser_session.user.clone())
            .await?;

        // and then schedule a job to deactivate it fully
        repo.queue_job()
            .schedule_job(
                &mut rng,
                &clock,
                DeactivateUserJob::new(&user, input.hs_erase),
            )
            .await?;

        repo.save().await?;

        Ok(DeactivateUserPayload::Deactivated(user))
    }
}
