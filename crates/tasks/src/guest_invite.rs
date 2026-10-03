// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Sending guest invite emails

use async_trait::async_trait;
use mas_email::{Address, Mailbox};
use mas_i18n::locale;
use mas_storage::queue::SendGuestInviteEmailJob;
use mas_templates::{EmailGuestInviteContext, TemplateContext as _};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for SendGuestInviteEmailJob {
    #[tracing::instrument(
        name = "job.send_guest_invite_email",
        fields(
            room.id = self.room_id(),
            user_registration_token.id = %self.registration_token_id(),
        ),
        skip_all,
    )]
    async fn run(&self, state: &State, _context: JobContext) -> Result<(), JobError> {
        let mailer = state.mailer();
        let url_builder = state.url_builder();
        let mut repo = state.repository().await.map_err(JobError::retry)?;

        let token = repo
            .user_registration_token()
            .lookup(self.registration_token_id())
            .await
            .map_err(JobError::retry)?
            .ok_or_else(|| JobError::fail(anyhow::anyhow!("Registration token not found")))?;
        repo.cancel().await.map_err(JobError::retry)?;

        if !token.is_valid(state.clock().now()) {
            info!("Registration token is no longer valid, not sending the invite");
            return Ok(());
        }

        let email = token.email.ok_or_else(|| {
            JobError::fail(anyhow::anyhow!(
                "Registration token has no email address pinned to it"
            ))
        })?;

        // A malformed address will never parse, however many times we retry
        let address: Address = email.parse().map_err(JobError::fail)?;
        let mailbox = Mailbox::new(None, address);

        // Recipients have no account, so no language preference to look up
        let context = EmailGuestInviteContext::new(
            self.room_name().map(ToOwned::to_owned),
            self.inviter().map(ToOwned::to_owned),
            self.inviter_name().map(ToOwned::to_owned),
            url_builder.guest_invite_link(self.room_id().to_owned(), token.token),
        )
        .with_language(locale!("en").into());

        info!("Sending guest invite email to {}", mailbox);
        mailer
            .send_guest_invite_email(mailbox, &context)
            .await
            .map_err(JobError::retry)?;

        Ok(())
    }
}
