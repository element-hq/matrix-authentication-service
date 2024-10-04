// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use apalis::{prelude::WorkerFactoryFn, utils::TokioExecutor};
use apalis_core::{layers::extensions::Data, monitor::Monitor};
use apalis_sql::postgres::PgListen;
use mas_email::{Address, AddressError, Mailbox};
use mas_i18n::DataLocale;
use mas_storage::{
    job::{JobWithSpanContext, SendAccountRecoveryEmailsJob},
    user::{UserEmailFilter, UserRecoveryRepository},
    Pagination, RepositoryAccess, RepositoryError,
};
use mas_storage_pg::DatabaseError;
use mas_templates::{EmailRecoveryContext, TemplateContext};
use rand::distributions::{Alphanumeric, DistString};
use tracing::{error, info};
use ulid::Ulid;

use crate::State;

#[derive(Debug, thiserror::Error)]
enum RecoveryJobError {
    #[error("User recovery session {0} not found")]
    UserRecoverySessionNotFound(Ulid),

    #[error("User email {0} not found")]
    UserEmailNotFound(Ulid),

    #[error("User {0} not found")]
    UserNotFound(Ulid),

    #[error("Invalid email address")]
    InvalidEmailAddress(#[from] AddressError),

    #[error("Invalid locale in database on recovery session")]
    InvalidLocale,

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

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
    state: Data<State>,
) -> Result<(), RecoveryJobError> {
    let clock = state.clock();
    let mailer = state.mailer();
    let url_builder = state.url_builder();
    let mut rng = state.rng();
    let mut repo = state.repository().await?;

    let session = repo
        .user_recovery()
        .lookup_session(job.user_recovery_session_id())
        .await?
        .ok_or(RecoveryJobError::UserRecoverySessionNotFound(
            job.user_recovery_session_id(),
        ))?;

    tracing::Span::current().record("user_recovery_session.email", &session.email);

    if session.consumed_at.is_some() {
        info!("Recovery session already consumed, not sending email");
        return Ok(());
    }

    let mut cursor = Pagination::first(50);

    let lang: DataLocale = session
        .locale
        .parse()
        .map_err(|_| RecoveryJobError::InvalidLocale)?;

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
                .ok_or(RecoveryJobError::UserEmailNotFound(email.id))?;

            let user = repo
                .user()
                .lookup(user_email.user_id)
                .await?
                .ok_or(RecoveryJobError::UserNotFound(user_email.user_id))?;

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
    monitor: Monitor<TokioExecutor>,
    state: &State,
    listener: &mut PgListen,
) -> Monitor<TokioExecutor> {
    let send_user_recovery_email_worker = state
        .pg_worker(listener)
        .build_fn(send_account_recovery_email_job);

    monitor.register(send_user_recovery_email_worker)
}
