// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::{DateTime, Utc};
use mas_data_model::{
    BrowserSession, CompatSession, Device, Session, User, UserEmailAuthentication,
    UserRecoverySession,
};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::InsertableJob;
use crate::{Page, Pagination};

/// This is the previous iteration of the email verification job. It has been
/// replaced by [`SendEmailAuthenticationCodeJob`]. This struct is kept to be
/// able to consume jobs that are still in the queue.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyEmailJob {
    user_email_id: Ulid,
    language: Option<String>,
}

impl VerifyEmailJob {
    /// The ID of the email address to verify.
    #[must_use]
    pub fn user_email_id(&self) -> Ulid {
        self.user_email_id
    }
}

impl InsertableJob for VerifyEmailJob {
    const QUEUE_NAME: &'static str = "verify-email";
}

/// A job to send an email authentication code to a user.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendEmailAuthenticationCodeJob {
    user_email_authentication_id: Ulid,
    language: String,
}

impl SendEmailAuthenticationCodeJob {
    /// Create a new job to send an email authentication code to a user.
    #[must_use]
    pub fn new(user_email_authentication: &UserEmailAuthentication, language: String) -> Self {
        Self {
            user_email_authentication_id: user_email_authentication.id,
            language,
        }
    }

    /// The language to use for the email.
    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The ID of the email authentication to send the code for.
    #[must_use]
    pub fn user_email_authentication_id(&self) -> Ulid {
        self.user_email_authentication_id
    }
}

impl InsertableJob for SendEmailAuthenticationCodeJob {
    const QUEUE_NAME: &'static str = "send-email-authentication-code";
}

/// A job to provision the user on the homeserver.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvisionUserJob {
    user_id: Ulid,
    set_display_name: Option<String>,
}

impl ProvisionUserJob {
    /// Create a new job to provision the user on the homeserver.
    #[must_use]
    pub fn new(user: &User) -> Self {
        Self {
            user_id: user.id,
            set_display_name: None,
        }
    }

    #[doc(hidden)]
    #[must_use]
    pub fn new_for_id(user_id: Ulid) -> Self {
        Self {
            user_id,
            set_display_name: None,
        }
    }

    /// Set the display name of the user.
    #[must_use]
    pub fn set_display_name(mut self, display_name: String) -> Self {
        self.set_display_name = Some(display_name);
        self
    }

    /// Get the display name to be set.
    #[must_use]
    pub fn display_name_to_set(&self) -> Option<&str> {
        self.set_display_name.as_deref()
    }

    /// The ID of the user to provision.
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }
}

impl InsertableJob for ProvisionUserJob {
    const QUEUE_NAME: &'static str = "provision-user";
}

/// A job to provision a device for a user on the homeserver.
///
/// This job is deprecated, use the `SyncDevicesJob` instead. It is kept to
/// not break existing jobs in the database.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProvisionDeviceJob {
    user_id: Ulid,
    device_id: String,
}

impl ProvisionDeviceJob {
    /// The ID of the user to provision the device for.
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }

    /// The ID of the device to provision.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

impl InsertableJob for ProvisionDeviceJob {
    const QUEUE_NAME: &'static str = "provision-device";
}

/// A job to delete a device for a user on the homeserver.
///
/// This job is deprecated, use the `SyncDevicesJob` instead. It is kept to
/// not break existing jobs in the database.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeleteDeviceJob {
    user_id: Ulid,
    device_id: String,
}

impl DeleteDeviceJob {
    /// Create a new job to delete a device for a user on the homeserver.
    #[must_use]
    pub fn new(user: &User, device: &Device) -> Self {
        Self {
            user_id: user.id,
            device_id: device.as_str().to_owned(),
        }
    }

    /// The ID of the user to delete the device for.
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }

    /// The ID of the device to delete.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

impl InsertableJob for DeleteDeviceJob {
    const QUEUE_NAME: &'static str = "delete-device";
}

/// A job which syncs the list of devices of a user with the homeserver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SyncDevicesJob {
    user_id: Ulid,
}

impl SyncDevicesJob {
    /// Create a new job to sync the list of devices of a user with the
    /// homeserver
    #[must_use]
    pub fn new(user: &User) -> Self {
        Self { user_id: user.id }
    }

    /// Create a new job to sync the list of devices of a user with the
    /// homeserver for the given user ID
    ///
    /// This is useful to use in cases where the [`User`] object isn't loaded
    #[must_use]
    pub fn new_for_id(user_id: Ulid) -> Self {
        Self { user_id }
    }

    /// The ID of the user to sync the devices for
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }
}

impl InsertableJob for SyncDevicesJob {
    const QUEUE_NAME: &'static str = "sync-devices";
}

/// A job to deactivate and lock a user
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeactivateUserJob {
    user_id: Ulid,
    hs_erase: bool,
}

impl DeactivateUserJob {
    /// Create a new job to deactivate and lock a user
    ///
    /// # Parameters
    ///
    /// * `user` - The user to deactivate
    /// * `hs_erase` - Whether to erase the user from the homeserver
    #[must_use]
    pub fn new(user: &User, hs_erase: bool) -> Self {
        Self {
            user_id: user.id,
            hs_erase,
        }
    }

    /// The ID of the user to deactivate
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }

    /// Whether to erase the user from the homeserver
    #[must_use]
    pub fn hs_erase(&self) -> bool {
        self.hs_erase
    }
}

impl InsertableJob for DeactivateUserJob {
    const QUEUE_NAME: &'static str = "deactivate-user";
}

/// A job to reactivate a user
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReactivateUserJob {
    user_id: Ulid,
}

impl ReactivateUserJob {
    /// Create a new job to reactivate a user
    ///
    /// # Parameters
    ///
    /// * `user` - The user to reactivate
    #[must_use]
    pub fn new(user: &User) -> Self {
        Self { user_id: user.id }
    }

    /// The ID of the user to reactivate
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }
}

impl InsertableJob for ReactivateUserJob {
    const QUEUE_NAME: &'static str = "reactivate-user";
}

/// Send account recovery emails
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendAccountRecoveryEmailsJob {
    user_recovery_session_id: Ulid,
}

impl SendAccountRecoveryEmailsJob {
    /// Create a new job to send account recovery emails
    ///
    /// # Parameters
    ///
    /// * `user_recovery_session` - The user recovery session to send the email
    ///   for
    /// * `language` - The locale to send the email in
    #[must_use]
    pub fn new(user_recovery_session: &UserRecoverySession) -> Self {
        Self {
            user_recovery_session_id: user_recovery_session.id,
        }
    }

    /// The ID of the user recovery session to send the email for
    #[must_use]
    pub fn user_recovery_session_id(&self) -> Ulid {
        self.user_recovery_session_id
    }
}

impl InsertableJob for SendAccountRecoveryEmailsJob {
    const QUEUE_NAME: &'static str = "send-account-recovery-email";
}

/// Cleanup expired tokens
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupExpiredTokensJob;

impl InsertableJob for CleanupExpiredTokensJob {
    const QUEUE_NAME: &'static str = "cleanup-expired-tokens";
}

/// Scheduled job to expire inactive sessions
///
/// This job will trigger jobs to expire inactive compat, oauth and user
/// sessions.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExpireInactiveSessionsJob;

impl InsertableJob for ExpireInactiveSessionsJob {
    const QUEUE_NAME: &'static str = "expire-inactive-sessions";
}

/// Expire inactive OAuth 2.0 sessions
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExpireInactiveOAuthSessionsJob {
    threshold: DateTime<Utc>,
    after: Option<Ulid>,
}

impl ExpireInactiveOAuthSessionsJob {
    /// Create a new job to expire inactive OAuth 2.0 sessions
    ///
    /// # Parameters
    ///
    /// * `threshold` - The threshold to expire sessions at
    #[must_use]
    pub fn new(threshold: DateTime<Utc>) -> Self {
        Self {
            threshold,
            after: None,
        }
    }

    /// Get the threshold to expire sessions at
    #[must_use]
    pub fn threshold(&self) -> DateTime<Utc> {
        self.threshold
    }

    /// Get the pagination cursor
    #[must_use]
    pub fn pagination(&self, batch_size: usize) -> Pagination {
        let pagination = Pagination::first(batch_size);
        if let Some(after) = self.after {
            pagination.after(after)
        } else {
            pagination
        }
    }

    /// Get the next job given the page returned by the database
    #[must_use]
    pub fn next(&self, page: &Page<Session>) -> Option<Self> {
        if !page.has_next_page {
            return None;
        }

        let last_edge = page.edges.last()?;
        Some(Self {
            threshold: self.threshold,
            after: Some(last_edge.id),
        })
    }
}

impl InsertableJob for ExpireInactiveOAuthSessionsJob {
    const QUEUE_NAME: &'static str = "expire-inactive-oauth-sessions";
}

/// Expire inactive compatibility sessions
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExpireInactiveCompatSessionsJob {
    threshold: DateTime<Utc>,
    after: Option<Ulid>,
}

impl ExpireInactiveCompatSessionsJob {
    /// Create a new job to expire inactive compatibility sessions
    ///
    /// # Parameters
    ///
    /// * `threshold` - The threshold to expire sessions at
    #[must_use]
    pub fn new(threshold: DateTime<Utc>) -> Self {
        Self {
            threshold,
            after: None,
        }
    }

    /// Get the threshold to expire sessions at
    #[must_use]
    pub fn threshold(&self) -> DateTime<Utc> {
        self.threshold
    }

    /// Get the pagination cursor
    #[must_use]
    pub fn pagination(&self, batch_size: usize) -> Pagination {
        let pagination = Pagination::first(batch_size);
        if let Some(after) = self.after {
            pagination.after(after)
        } else {
            pagination
        }
    }

    /// Get the next job given the page returned by the database
    #[must_use]
    pub fn next(&self, page: &Page<CompatSession>) -> Option<Self> {
        if !page.has_next_page {
            return None;
        }

        let last_edge = page.edges.last()?;
        Some(Self {
            threshold: self.threshold,
            after: Some(last_edge.id),
        })
    }
}

impl InsertableJob for ExpireInactiveCompatSessionsJob {
    const QUEUE_NAME: &'static str = "expire-inactive-compat-sessions";
}

/// Expire inactive user sessions
#[derive(Debug, Serialize, Deserialize)]
pub struct ExpireInactiveUserSessionsJob {
    threshold: DateTime<Utc>,
    after: Option<Ulid>,
}

impl ExpireInactiveUserSessionsJob {
    /// Create a new job to expire inactive user/browser sessions
    ///
    /// # Parameters
    ///
    /// * `threshold` - The threshold to expire sessions at
    #[must_use]
    pub fn new(threshold: DateTime<Utc>) -> Self {
        Self {
            threshold,
            after: None,
        }
    }

    /// Get the threshold to expire sessions at
    #[must_use]
    pub fn threshold(&self) -> DateTime<Utc> {
        self.threshold
    }

    /// Get the pagination cursor
    #[must_use]
    pub fn pagination(&self, batch_size: usize) -> Pagination {
        let pagination = Pagination::first(batch_size);
        if let Some(after) = self.after {
            pagination.after(after)
        } else {
            pagination
        }
    }

    /// Get the next job given the page returned by the database
    #[must_use]
    pub fn next(&self, page: &Page<BrowserSession>) -> Option<Self> {
        if !page.has_next_page {
            return None;
        }

        let last_edge = page.edges.last()?;
        Some(Self {
            threshold: self.threshold,
            after: Some(last_edge.id),
        })
    }
}

impl InsertableJob for ExpireInactiveUserSessionsJob {
    const QUEUE_NAME: &'static str = "expire-inactive-user-sessions";
}

/// Prune stale policy data
#[derive(Debug, Serialize, Deserialize)]
pub struct PruneStalePolicyDataJob;

impl InsertableJob for PruneStalePolicyDataJob {
    const QUEUE_NAME: &'static str = "prune-stale-policy-data";
}
