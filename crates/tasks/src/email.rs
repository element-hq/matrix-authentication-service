// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context;
use async_trait::async_trait;
use chrono::Duration;
use mas_email::{Address, Mailbox};
use mas_i18n::locale;
use mas_storage::queue::VerifyEmailJob;
use mas_templates::{EmailVerificationContext, TemplateContext};
use rand::{distributions::Uniform, Rng};
use tracing::info;

use crate::{
    new_queue::{JobContext, JobError, RunnableJob},
    State,
};

#[async_trait]
impl RunnableJob for VerifyEmailJob {
    #[tracing::instrument(
        name = "job.verify_email",
        fields(user_email.id = %self.user_email_id()),
        skip_all,
        err,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mut repo = state.repository().await.map_err(JobError::retry)?;
        let mut rng = state.rng();
        let mailer = state.mailer();
        let clock = state.clock();

        let language = self
            .language()
            .and_then(|l| l.parse().ok())
            .unwrap_or(locale!("en").into());

        // Lookup the user email
        let user_email = repo
            .user_email()
            .lookup(self.user_email_id())
            .await
            .map_err(JobError::retry)?
            .context("User email not found")
            .map_err(JobError::fail)?;

        // Lookup the user associated with the email
        let user = repo
            .user()
            .lookup(user_email.user_id)
            .await
            .map_err(JobError::retry)?
            .context("User not found")
            .map_err(JobError::fail)?;

        // Generate a verification code
        let range = Uniform::<u32>::from(0..1_000_000);
        let code = rng.sample(range);
        let code = format!("{code:06}");

        let address: Address = user_email.email.parse().map_err(JobError::fail)?;

        // Save the verification code in the database
        let verification = repo
            .user_email()
            .add_verification_code(
                &mut rng,
                &clock,
                &user_email,
                Duration::try_hours(8).unwrap(),
                code,
            )
            .await
            .map_err(JobError::retry)?;

        // And send the verification email
        let mailbox = Mailbox::new(Some(user.username.clone()), address);

        let context = EmailVerificationContext::new(user.clone(), verification.clone())
            .with_language(language);

        mailer
            .send_verification_email(mailbox, &context)
            .await
            .map_err(JobError::retry)?;

        info!(
            email.id = %user_email.id,
            "Verification email sent"
        );

        repo.save().await.map_err(JobError::retry)?;

        Ok(())
    }
}
