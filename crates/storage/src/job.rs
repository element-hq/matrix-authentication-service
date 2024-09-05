// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Repository to schedule persistent jobs.

use std::{num::ParseIntError, ops::Deref};

pub use apalis_core::job::{Job, JobId};
use async_trait::async_trait;
use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::repository_impl;

/// A job submission to be scheduled through the repository.
pub struct JobSubmission {
    name: &'static str,
    payload: Value,
}

#[derive(Serialize, Deserialize)]
struct SerializableSpanContext {
    trace_id: String,
    span_id: String,
    trace_flags: u8,
}

impl From<&SpanContext> for SerializableSpanContext {
    fn from(value: &SpanContext) -> Self {
        Self {
            trace_id: value.trace_id().to_string(),
            span_id: value.span_id().to_string(),
            trace_flags: value.trace_flags().to_u8(),
        }
    }
}

impl TryFrom<&SerializableSpanContext> for SpanContext {
    type Error = ParseIntError;

    fn try_from(value: &SerializableSpanContext) -> Result<Self, Self::Error> {
        Ok(SpanContext::new(
            TraceId::from_hex(&value.trace_id)?,
            SpanId::from_hex(&value.span_id)?,
            TraceFlags::new(value.trace_flags),
            // XXX: is that fine?
            true,
            TraceState::default(),
        ))
    }
}

/// A wrapper for [`Job`] which adds the span context in the payload.
#[derive(Serialize, Deserialize)]
pub struct JobWithSpanContext<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    span_context: Option<SerializableSpanContext>,

    #[serde(flatten)]
    payload: T,
}

impl<J> From<J> for JobWithSpanContext<J> {
    fn from(payload: J) -> Self {
        Self {
            span_context: None,
            payload,
        }
    }
}

impl<J: Job> Job for JobWithSpanContext<J> {
    const NAME: &'static str = J::NAME;
}

impl<T> Deref for JobWithSpanContext<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl<T> JobWithSpanContext<T> {
    /// Get the span context of the job.
    ///
    /// # Returns
    ///
    /// Returns [`None`] if the job has no span context, or if the span context
    /// is invalid.
    #[must_use]
    pub fn span_context(&self) -> Option<SpanContext> {
        self.span_context
            .as_ref()
            .and_then(|ctx| ctx.try_into().ok())
    }
}

impl JobSubmission {
    /// Create a new job submission out of a [`Job`].
    ///
    /// # Panics
    ///
    /// Panics if the job cannot be serialized.
    #[must_use]
    pub fn new<J: Job + Serialize>(job: J) -> Self {
        let payload = serde_json::to_value(job).expect("Could not serialize job");

        Self {
            name: J::NAME,
            payload,
        }
    }

    /// Create a new job submission out of a [`Job`] and a [`SpanContext`].
    ///
    /// # Panics
    ///
    /// Panics if the job cannot be serialized.
    #[must_use]
    pub fn new_with_span_context<J: Job + Serialize>(job: J, span_context: &SpanContext) -> Self {
        // Serialize the span context alongside the job.
        let span_context = SerializableSpanContext::from(span_context);

        Self::new(JobWithSpanContext {
            payload: job,
            span_context: Some(span_context),
        })
    }

    /// The name of the job.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The payload of the job.
    #[must_use]
    pub fn payload(&self) -> &Value {
        &self.payload
    }
}

/// A [`JobRepository`] is used to schedule jobs to be executed by a worker.
#[async_trait]
pub trait JobRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Schedule a job submission to be executed at a later time.
    ///
    /// # Parameters
    ///
    /// * `submission` - The job to schedule.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn schedule_submission(
        &mut self,
        submission: JobSubmission,
    ) -> Result<JobId, Self::Error>;
}

repository_impl!(JobRepository:
    async fn schedule_submission(&mut self, submission: JobSubmission) -> Result<JobId, Self::Error>;
);

/// An extension trait for [`JobRepository`] to schedule jobs directly.
#[async_trait]
pub trait JobRepositoryExt {
    /// The error type returned by the repository.
    type Error;

    /// Schedule a job to be executed at a later time.
    ///
    /// # Parameters
    ///
    /// * `job` - The job to schedule.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the underlying repository fails
    async fn schedule_job<J: Job + Serialize + Send>(
        &mut self,
        job: J,
    ) -> Result<JobId, Self::Error>;
}

#[async_trait]
impl<T> JobRepositoryExt for T
where
    T: JobRepository + ?Sized,
{
    type Error = T::Error;

    #[tracing::instrument(
        name = "db.job.schedule_job",
        skip_all,
        fields(
            job.name = J::NAME,
        ),
    )]
    async fn schedule_job<J: Job + Serialize + Send>(
        &mut self,
        job: J,
    ) -> Result<JobId, Self::Error> {
        let span = tracing::Span::current();
        let ctx = span.context();
        let span = ctx.span();
        let span_context = span.span_context();

        self.schedule_submission(JobSubmission::new_with_span_context(job, span_context))
            .await
    }
}

mod jobs {
    // XXX: Move this somewhere else?
    use apalis_core::job::Job;
    use mas_data_model::{Device, User, UserEmail, UserRecoverySession};
    use serde::{Deserialize, Serialize};
    use ulid::Ulid;

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

    impl Job for VerifyEmailJob {
        const NAME: &'static str = "verify-email";
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

    impl Job for ProvisionUserJob {
        const NAME: &'static str = "provision-user";
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

    impl Job for ProvisionDeviceJob {
        const NAME: &'static str = "provision-device";
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

    impl Job for DeleteDeviceJob {
        const NAME: &'static str = "delete-device";
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

    impl Job for SyncDevicesJob {
        const NAME: &'static str = "sync-devices";
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

    impl Job for DeactivateUserJob {
        const NAME: &'static str = "deactivate-user";
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

    impl Job for ReactivateUserJob {
        const NAME: &'static str = "reactivate-user";
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
        /// * `user_recovery_session` - The user recovery session to send the
        ///   email for
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

    impl Job for SendAccountRecoveryEmailsJob {
        const NAME: &'static str = "send-account-recovery-email";
    }
}

pub use self::jobs::{
    DeactivateUserJob, DeleteDeviceJob, ProvisionDeviceJob, ProvisionUserJob, ReactivateUserJob,
    SendAccountRecoveryEmailsJob, SyncDevicesJob, VerifyEmailJob,
};
