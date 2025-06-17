// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use chrono::Duration;
use mas_email::{Address, EmailVerificationContext, Mailbox};
use mas_storage::queue::{SendEmailAuthenticationCodeJob, VerifyEmailJob};
use mas_templates::TemplateContext as _;
use rand::{Rng, distributions::Uniform};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for VerifyEmailJob {
    #[tracing::instrument(
        name = "job.verify_email",
        fields(user_email.id = %self.user_email_id()),
        skip_all,
    )]
    async fn run(&self, _state: &State, _context: JobContext) -> Result<(), JobError> {
        // This job was for the old email verification flow, which has been replaced.
        // We still want to consume existing jobs in the queue, so we just make them
        // permanently fail.
        Err(JobError::fail(anyhow::anyhow!("Not implemented")))
    }
}

#[async_trait]
impl RunnableJob for SendEmailAuthenticationCodeJob {
    #[tracing::instrument(
        name = "job.send_email_authentication_code",
        fields(user_email_authentication.id = %self.user_email_authentication_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let mailer = state.mailer();
        let mut rng = state.rng();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let user_email_authentication = repo
            .user_email()
            .lookup_authentication(self.user_email_authentication_id())
            .await
            .map_err(JobError::retry)?
            .ok_or(JobError::fail(anyhow::anyhow!(
                "User email authentication not found"
            )))?;

        if user_email_authentication.completed_at.is_some() {
            return Err(JobError::fail(anyhow::anyhow!(
                "User email authentication already completed"
            )));
        }

        // Load the browser session, if any
        let browser_session =
            if let Some(browser_session) = user_email_authentication.user_session_id {
                Some(
                    repo.browser_session()
                        .lookup(browser_session)
                        .await
                        .map_err(JobError::retry)?
                        .ok_or(JobError::fail(anyhow::anyhow!(
                            "Failed to load browser session"
                        )))?,
                )
            } else {
                None
            };

        // Load the registration, if any
        let registration =
            if let Some(registration_id) = user_email_authentication.user_registration_id {
                Some(
                    repo.user_registration()
                        .lookup(registration_id)
                        .await
                        .map_err(JobError::retry)?
                        .ok_or(JobError::fail(anyhow::anyhow!(
                            "Failed to load user registration"
                        )))?,
                )
            } else {
                None
            };

        // Generate a new 6-digit authentication code
        let range = Uniform::<u32>::from(0..1_000_000);
        let code = rng.sample(range);
        let code = format!("{code:06}");
        let code = repo
            .user_email()
            .add_authentication_code(
                &mut rng,
                &clock,
                Duration::minutes(5), // TODO: make this configurable
                &user_email_authentication,
                code,
            )
            .await
            .map_err(JobError::retry)?;

        let address: Address = user_email_authentication
            .email
            .parse()
            .map_err(JobError::fail)?;
        let username_from_session = browser_session.as_ref().map(|s| s.user.username.clone());
        let username_from_registration = registration.as_ref().map(|r| r.username.clone());
        let username = username_from_registration.or(username_from_session);
        let mailbox = Mailbox::new(username, address);

        info!("Sending email verification code to {}", mailbox);

        let language = self.language().parse().map_err(JobError::fail)?;

        let context = EmailVerificationContext::new(code, browser_session, registration)
            .with_language(language);
        mailer
            .send_verification_email(mailbox, &context)
            .await
            .map_err(JobError::fail)?;

        repo.save().await.map_err(JobError::fail)?;

        Ok(())
    }
}
