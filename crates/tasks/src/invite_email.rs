// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Sending invite emails

use async_trait::async_trait;
use mas_email::{Address, Mailbox};
use mas_i18n::locale;
use mas_storage::queue::SendInviteEmailJob;
use mas_templates::{EmailInviteContext, TemplateContext as _};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

#[async_trait]
impl RunnableJob for SendInviteEmailJob {
    #[tracing::instrument(
        name = "job.send_invite_email",
        fields(
            room.id = tracing::field::Empty,
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
        tracing::Span::current().record("room.id", token.room_id.as_deref());

        if !token.is_valid(state.clock().now()) {
            info!("Registration token is no longer valid, not sending the invite");
            return Ok(());
        }

        // A malformed address will never parse, however many times we retry
        let address: Address = self.email().parse().map_err(JobError::fail)?;
        let mailbox = Mailbox::new(None, address);

        // Recipients have no account, so no language preference to look up
        let context = EmailInviteContext::new(
            token.room_id.is_some(),
            self.room_name().map(ToOwned::to_owned),
            self.inviter().map(ToOwned::to_owned),
            self.inviter_name().map(ToOwned::to_owned),
            url_builder.absolute_url_for(&mas_router::Register::default().with_token(token.token)),
        )
        .with_language(locale!("en").into());

        info!("Sending invite email to {}", mailbox);
        mailer
            .send_invite_email(mailbox, &context)
            .await
            .map_err(JobError::retry)?;

        Ok(())
    }
}
