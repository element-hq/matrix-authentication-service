// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Sending room invite emails

use std::collections::HashSet;

use async_trait::async_trait;
use chrono::Duration;
use mas_email::{Address, Mailbox};
use mas_i18n::DataLocale;
use mas_storage::queue::{
    QueueJobRepositoryExt as _, SendRoomInviteEmailJob, SendRoomInviteEmailsJob,
};
use mas_templates::{EmailRoomInviteContext, TemplateContext as _};
use tracing::info;
use url::Url;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

/// How much to space out the individual sends, so that a large batch doesn't
/// burst against the SMTP server. 100ms gives a ceiling of ~10 emails/second.
const SEND_INTERVAL: Duration = Duration::milliseconds(100);

/// The locale used for recipients, who have no account and therefore no
/// language preference we could look up.
const DEFAULT_LOCALE: &str = "en";

/// Build the link a recipient follows to accept the invite.
///
/// XXX: this is a stub. A real implementation has to decide what the link
/// points at — a `matrix.to` URL, a client deep-link, or a MAS-hosted landing
/// page — and most likely needs to create the invite on the homeserver first
/// (a third-party invite keyed on the email address), so that following the
/// link actually lets the recipient in.
fn room_invite_link(room_id: &str) -> Url {
    let mut url = Url::parse("https://matrix.to/").expect("static URL is valid");
    url.set_fragment(Some(&format!("/{room_id}")));
    url
}

#[async_trait]
impl RunnableJob for SendRoomInviteEmailsJob {
    #[tracing::instrument(
        name = "job.send_room_invite_emails",
        fields(
            room.id = self.room_id(),
            recipients.total = self.emails().len(),
            recipients.scheduled,
        ),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let clock = state.clock();
        let mut rng = state.rng();
        let now = clock.now();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        // One job per recipient, so that a bad address or a transient SMTP
        // failure retries that single email rather than the whole batch.
        let mut seen = HashSet::new();
        let mut delay = Duration::zero();

        for email in self.emails() {
            if !seen.insert(email.as_str()) {
                continue;
            }

            repo.queue_job()
                .schedule_job_later(
                    &mut rng,
                    clock,
                    SendRoomInviteEmailJob::new(self.room_id(), email),
                    now + delay,
                )
                .await
                .map_err(JobError::retry)?;

            delay += SEND_INTERVAL;
        }

        tracing::Span::current().record("recipients.scheduled", seen.len());

        // Committing the whole fan-out at once is what makes this job safe to
        // retry: either every recipient got a job, or none did.
        repo.save().await.map_err(JobError::retry)?;

        info!(
            "Scheduled {} room invite emails, spread over {}s",
            seen.len(),
            delay.num_seconds()
        );

        Ok(())
    }
}

#[async_trait]
impl RunnableJob for SendRoomInviteEmailJob {
    #[tracing::instrument(
        name = "job.send_room_invite_email",
        fields(room.id = self.room_id()),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mailer = state.mailer();

        // A malformed address will never parse, however many times we retry
        let address: Address = self.email().parse().map_err(JobError::fail)?;
        let mailbox = Mailbox::new(None, address);

        let lang: DataLocale = DEFAULT_LOCALE.parse().map_err(JobError::fail)?;
        let context = EmailRoomInviteContext::new(
            self.room_id().to_owned(),
            room_invite_link(self.room_id()),
        )
        .with_language(lang);

        info!("Sending room invite email to {}", mailbox);
        mailer
            .send_room_invite_email(mailbox, &context)
            .await
            .map_err(JobError::retry)?;

        Ok(())
    }
}
