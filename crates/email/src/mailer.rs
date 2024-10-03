// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Send emails to users

use lettre::{
    message::{Mailbox, MessageBuilder, MultiPart},
    AsyncTransport, Message,
};
use mas_templates::{EmailRecoveryContext, EmailVerificationContext, Templates, WithLanguage};
use thiserror::Error;

use crate::MailTransport;

/// Helps sending mails to users
#[derive(Clone)]
pub struct Mailer {
    templates: Templates,
    transport: MailTransport,
    from: Mailbox,
    reply_to: Mailbox,
}

/// Error sending an email
#[derive(Debug, Error)]
#[error(transparent)]
pub enum Error {
    /// Transport failed to send the email
    Transport(#[from] crate::transport::Error),

    /// Template failed to render the email
    Templates(#[from] mas_templates::TemplateError),

    /// Invalid email content
    Content(#[from] lettre::error::Error),
}

impl Mailer {
    /// Constructs a new [`Mailer`]
    #[must_use]
    pub fn new(
        templates: Templates,
        transport: MailTransport,
        from: Mailbox,
        reply_to: Mailbox,
    ) -> Self {
        Self {
            templates,
            transport,
            from,
            reply_to,
        }
    }

    fn base_message(&self) -> MessageBuilder {
        Message::builder()
            .from(self.from.clone())
            .reply_to(self.reply_to.clone())
    }

    fn prepare_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
    ) -> Result<Message, Error> {
        let plain = self.templates.render_email_verification_txt(context)?;

        let html = self.templates.render_email_verification_html(context)?;

        let multipart = MultiPart::alternative_plain_html(plain, html);

        let subject = self.templates.render_email_verification_subject(context)?;

        let message = self
            .base_message()
            .subject(subject.trim())
            .to(to)
            .multipart(multipart)?;

        Ok(message)
    }

    fn prepare_recovery_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
    ) -> Result<Message, Error> {
        let plain = self.templates.render_email_recovery_txt(context)?;

        let html = self.templates.render_email_recovery_html(context)?;

        let multipart = MultiPart::alternative_plain_html(plain, html);

        let subject = self.templates.render_email_recovery_subject(context)?;

        let message = self
            .base_message()
            .subject(subject.trim())
            .to(to)
            .multipart(multipart)?;

        Ok(message)
    }

    /// Send the verification email to a user
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending
    #[tracing::instrument(
        name = "email.verification.send",
        skip_all,
        fields(
            email.to = %to,
            email.language = %context.language(),
            user.id = %context.user().id,
            user_email_verification.id = %context.verification().id,
            user_email_verification.code = context.verification().code,
        ),
        err,
    )]
    pub async fn send_verification_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailVerificationContext>,
    ) -> Result<(), Error> {
        let message = self.prepare_verification_email(to, context)?;
        self.transport.send(message).await?;
        Ok(())
    }

    /// Send the recovery email to a user
    ///
    /// # Errors
    ///
    /// Will return `Err` if the email failed rendering or failed sending
    #[tracing::instrument(
        name = "email.recovery.send",
        skip_all,
        fields(
            email.to = %to,
            email.language = %context.language(),
            user.id = %context.user().id,
            user_recovery_session.id = %context.session().id,
        ),
        err,
    )]
    pub async fn send_recovery_email(
        &self,
        to: Mailbox,
        context: &WithLanguage<EmailRecoveryContext>,
    ) -> Result<(), Error> {
        let message = self.prepare_recovery_email(to, context)?;
        self.transport.send(message).await?;
        Ok(())
    }

    /// Test the connetion to the mail server
    ///
    /// # Errors
    ///
    /// Returns an error if the connection failed
    #[tracing::instrument(name = "email.test_connection", skip_all, err)]
    pub async fn test_connection(&self) -> Result<(), crate::transport::Error> {
        self.transport.test_connection().await
    }
}
