// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Sending room invite emails

use async_trait::async_trait;
use mas_email::{Address, Mailbox};
use mas_i18n::DataLocale;
use mas_router::Invite;
use mas_storage::queue::SendRoomInviteEmailJob;
use mas_templates::{EmailRoomInviteContext, TemplateContext as _};
use tracing::info;

use crate::{
    State,
    new_queue::{JobContext, JobError, RunnableJob},
};

/// The locale used for recipients, who have no account and therefore no
/// language preference we could look up.
const DEFAULT_LOCALE: &str = "en";

#[async_trait]
impl RunnableJob for SendRoomInviteEmailJob {
    #[tracing::instrument(
        name = "job.send_room_invite_email",
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

        // The address is the one the token is pinned to, so the invite link can
        // only ever be sent to the recipient it was minted for
        let email = token.email.ok_or_else(|| {
            JobError::fail(anyhow::anyhow!(
                "Registration token has no email address pinned to it"
            ))
        })?;

        // A malformed address will never parse, however many times we retry
        let address: Address = email.parse().map_err(JobError::fail)?;
        let mailbox = Mailbox::new(None, address);

        let lang: DataLocale = DEFAULT_LOCALE.parse().map_err(JobError::fail)?;
        let context = EmailRoomInviteContext::new(
            self.room_id().to_owned(),
            url_builder.absolute_url_for(&Invite::new(token.token)),
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
