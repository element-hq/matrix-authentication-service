// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use mas_data_model::{Device, User, UserEmail, UserRecoverySession};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::InsertableJob;

/// A job to verify an email address.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerifyEmailJob {
    user_email_id: Ulid,
    language: Option<String>,
}

impl VerifyEmailJob {
    /// Create a new job to verify an email address.
    #[must_use]
    pub fn new(user_email: &UserEmail) -> Self {
        Self {
            user_email_id: user_email.id,
            language: None,
        }
    }

    /// Set the language to use for the email.
    #[must_use]
    pub fn with_language(mut self, language: String) -> Self {
        self.language = Some(language);
        self
    }

    /// The language to use for the email.
    #[must_use]
    pub fn language(&self) -> Option<&str> {
        self.language.as_deref()
    }

    /// The ID of the email address to verify.
    #[must_use]
    pub fn user_email_id(&self) -> Ulid {
        self.user_email_id
    }
}

// Implemented for compatibility
impl apalis_core::job::Job for VerifyEmailJob {
    const NAME: &'static str = "verify-email";
}

impl InsertableJob for VerifyEmailJob {
    const QUEUE_NAME: &'static str = "verify-email";
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

// Implemented for compatibility
impl apalis_core::job::Job for ProvisionUserJob {
    const NAME: &'static str = "provision-user";
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

// Implemented for compatibility with older versions
impl apalis_core::job::Job for ProvisionDeviceJob {
    const NAME: &'static str = "provision-device";
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

// Implemented for compatibility with older versions
impl apalis_core::job::Job for DeleteDeviceJob {
    const NAME: &'static str = "delete-device";
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

    /// The ID of the user to sync the devices for
    #[must_use]
    pub fn user_id(&self) -> Ulid {
        self.user_id
    }
}

// Implemented for compatibility with older versions
impl apalis_core::job::Job for SyncDevicesJob {
    const NAME: &'static str = "sync-devices";
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

// Implemented for compatibility with older versions
impl apalis_core::job::Job for DeactivateUserJob {
    const NAME: &'static str = "deactivate-user";
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

// Implemented for compatibility with older versions
impl apalis_core::job::Job for ReactivateUserJob {
    const NAME: &'static str = "reactivate-user";
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

// Implemented for compatibility with older versions
impl apalis_core::job::Job for SendAccountRecoveryEmailsJob {
    const NAME: &'static str = "send-account-recovery-email";
}

impl InsertableJob for SendAccountRecoveryEmailsJob {
    const QUEUE_NAME: &'static str = "send-account-recovery-email";
}
