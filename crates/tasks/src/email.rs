// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context;
use apalis_core::{context::JobContext, executor::TokioExecutor, monitor::Monitor};
use chrono::Duration;
use mas_email::{Address, Mailbox};
use mas_i18n::locale;
use mas_storage::job::{JobWithSpanContext, VerifyEmailJob};
use mas_templates::{EmailVerificationContext, TemplateContext};
use rand::{distributions::Uniform, Rng};
use tracing::info;

use crate::{storage::PostgresStorageFactory, JobContextExt, State};

#[tracing::instrument(
    name = "job.verify_email",
    fields(user_email.id = %job.user_email_id()),
    skip_all,
    err(Debug),
)]
async fn verify_email(
    job: JobWithSpanContext<VerifyEmailJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let mut repo = state.repository().await?;
    let mut rng = state.rng();
    let mailer = state.mailer();
    let clock = state.clock();

    let language = job
        .language()
        .and_then(|l| l.parse().ok())
        .unwrap_or(locale!("en").into());

    // Lookup the user email
    let user_email = repo
        .user_email()
        .lookup(job.user_email_id())
        .await?
        .context("User email not found")?;

    // Lookup the user associated with the email
    let user = repo
        .user()
        .lookup(user_email.user_id)
        .await?
        .context("User not found")?;

    // Generate a verification code
    let range = Uniform::<u32>::from(0..1_000_000);
    let code = rng.sample(range);
    let code = format!("{code:06}");

    let address: Address = user_email.email.parse()?;

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
        .await?;

    // And send the verification email
    let mailbox = Mailbox::new(Some(user.username.clone()), address);

    let context =
        EmailVerificationContext::new(user.clone(), verification.clone()).with_language(language);

    mailer.send_verification_email(mailbox, &context).await?;

    info!(
        email.id = %user_email.id,
        "Verification email sent"
    );

    repo.save().await?;

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
    storage_factory: &PostgresStorageFactory,
) -> Monitor<TokioExecutor> {
    let verify_email_worker =
        crate::build!(VerifyEmailJob => verify_email, suffix, state, storage_factory);

    monitor.register(verify_email_worker)
}
