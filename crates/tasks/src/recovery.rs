// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context;
use apalis_core::{context::JobContext, executor::TokioExecutor, monitor::Monitor};
use mas_email::{Address, Mailbox};
use mas_i18n::DataLocale;
use mas_storage::{
    job::JobWithSpanContext,
    queue::SendAccountRecoveryEmailsJob,
    user::{UserEmailFilter, UserRecoveryRepository},
    Pagination, RepositoryAccess,
};
use mas_templates::{EmailRecoveryContext, TemplateContext};
use rand::distributions::{Alphanumeric, DistString};
use tracing::{error, info};

use crate::{storage::PostgresStorageFactory, JobContextExt, State};

/// Job to send account recovery emails for a given recovery session.
#[tracing::instrument(
    name = "job.send_account_recovery_email",
    fields(
        user_recovery_session.id = %job.user_recovery_session_id(),
        user_recovery_session.email,
    ),
    skip_all,
    err(Debug),
)]
async fn send_account_recovery_email_job(
    job: JobWithSpanContext<SendAccountRecoveryEmailsJob>,
    ctx: JobContext,
) -> Result<(), anyhow::Error> {
    let state = ctx.state();
    let clock = state.clock();
    let mailer = state.mailer();
    let url_builder = state.url_builder();
    let mut rng = state.rng();
    let mut repo = state.repository().await?;

    let session = repo
        .user_recovery()
        .lookup_session(job.user_recovery_session_id())
        .await?
        .context("User recovery session not found")?;

    tracing::Span::current().record("user_recovery_session.email", &session.email);

    if session.consumed_at.is_some() {
        info!("Recovery session already consumed, not sending email");
        return Ok(());
    }

    let mut cursor = Pagination::first(50);

    let lang: DataLocale = session
        .locale
        .parse()
        .context("Invalid locale in database on recovery session")?;

    loop {
        let page = repo
            .user_email()
            .list(
                UserEmailFilter::new()
                    .for_email(&session.email)
                    .verified_only(),
                cursor,
            )
            .await?;

        for email in page.edges {
            let ticket = Alphanumeric.sample_string(&mut rng, 32);

            let ticket = repo
                .user_recovery()
                .add_ticket(&mut rng, &clock, &session, &email, ticket)
                .await?;

            let user_email = repo
                .user_email()
                .lookup(email.id)
                .await?
                .context("User email not found")?;

            let user = repo
                .user()
                .lookup(user_email.user_id)
                .await?
                .context("User not found")?;

            let url = url_builder.account_recovery_link(ticket.ticket);

            let address: Address = user_email.email.parse()?;
            let mailbox = Mailbox::new(Some(user.username.clone()), address);

            info!("Sending recovery email to {}", mailbox);
            let context =
                EmailRecoveryContext::new(user, session.clone(), url).with_language(lang.clone());

            // XXX: we only log if the email fails to send, to avoid stopping the loop
            if let Err(e) = mailer.send_recovery_email(mailbox, &context).await {
                error!(
                    error = &e as &dyn std::error::Error,
                    "Failed to send recovery email"
                );
            }

            cursor = cursor.after(email.id);
        }

        if !page.has_next_page {
            break;
        }
    }

    repo.save().await?;

    Ok(())
}

pub(crate) fn register(
    suffix: &str,
    monitor: Monitor<TokioExecutor>,
    state: &State,
    storage_factory: &PostgresStorageFactory,
) -> Monitor<TokioExecutor> {
    let send_user_recovery_email_worker = crate::build!(SendAccountRecoveryEmailsJob => send_account_recovery_email_job, suffix, state, storage_factory);

    monitor.register(send_user_recovery_email_worker)
}
