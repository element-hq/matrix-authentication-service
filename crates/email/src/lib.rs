// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Helps sending emails to users, with different email backends

#![deny(missing_docs)]

mod mailer;
mod transport;

pub use lettre::{
    Address, message::Mailbox, transport::smtp::authentication::Credentials as SmtpCredentials,
};
pub use mas_templates::EmailVerificationContext;

pub use self::{
    mailer::Mailer,
    transport::{SmtpMode, Transport as MailTransport},
};
