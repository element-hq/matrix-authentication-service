// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(deprecated)]

use std::{num::NonZeroU16, str::FromStr};

use lettre::message::Mailbox;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};

use super::ConfigurationSection;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Credentials {
    /// Username for use to authenticate when connecting to the SMTP server
    pub username: String,

    /// Password for use to authenticate when connecting to the SMTP server
    pub password: String,
}

/// Encryption mode to use
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EmailSmtpMode {
    /// Plain text
    Plain,

    /// `StartTLS` (starts as plain text then upgrade to TLS)
    StartTls,

    /// TLS
    Tls,
}

/// What backend should be used when sending emails
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum EmailTransportKind {
    /// Don't send emails anywhere
    #[default]
    Blackhole,

    /// Send emails via an SMTP relay
    Smtp,

    /// Send emails by calling sendmail
    Sendmail,
}

fn default_email() -> String {
    r#""Authentication Service" <root@localhost>"#.to_owned()
}

#[allow(clippy::unnecessary_wraps)]
fn default_sendmail_command() -> Option<String> {
    Some("sendmail".to_owned())
}

/// Configuration related to sending emails
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EmailConfig {
    /// Email address to use as From when sending emails
    #[serde(default = "default_email")]
    #[schemars(email)]
    pub from: String,

    /// Email address to use as Reply-To when sending emails
    #[serde(default = "default_email")]
    #[schemars(email)]
    pub reply_to: String,

    /// What backend should be used when sending emails
    transport: EmailTransportKind,

    /// SMTP transport: Connection mode to the relay
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<EmailSmtpMode>,

    /// SMTP transport: Hostname to connect to
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<crate::schema::Hostname>")]
    hostname: Option<String>,

    /// SMTP transport: Port to connect to. Default is 25 for plain, 465 for TLS
    /// and 587 for `StartTLS`
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 65535))]
    port: Option<NonZeroU16>,

    /// SMTP transport: Username for use to authenticate when connecting to the
    /// SMTP server
    ///
    /// Must be set if the `password` field is set
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,

    /// SMTP transport: Password for use to authenticate when connecting to the
    /// SMTP server
    ///
    /// Must be set if the `username` field is set
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,

    /// Sendmail transport: Command to use to send emails
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(default = "default_sendmail_command")]
    command: Option<String>,
}

impl EmailConfig {
    /// What backend should be used when sending emails
    #[must_use]
    pub fn transport(&self) -> EmailTransportKind {
        self.transport
    }

    /// Connection mode to the relay
    #[must_use]
    pub fn mode(&self) -> Option<EmailSmtpMode> {
        self.mode
    }

    /// Hostname to connect to
    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Port to connect to
    #[must_use]
    pub fn port(&self) -> Option<NonZeroU16> {
        self.port
    }

    /// Username for use to authenticate when connecting to the SMTP server
    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Password for use to authenticate when connecting to the SMTP server
    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Command to use to send emails
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            from: default_email(),
            reply_to: default_email(),
            transport: EmailTransportKind::Blackhole,
            mode: None,
            hostname: None,
            port: None,
            username: None,
            password: None,
            command: None,
        }
    }
}

impl ConfigurationSection for EmailConfig {
    const PATH: Option<&'static str> = Some("email");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let metadata = figment.find_metadata(Self::PATH.unwrap());

        let error_on_field = |mut error: figment::error::Error, field: &'static str| {
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned(), field.to_owned()];
            error
        };

        let missing_field = |field: &'static str| {
            error_on_field(figment::error::Error::missing_field(field), field)
        };

        let unexpected_field = |field: &'static str, expected_fields: &'static [&'static str]| {
            error_on_field(
                figment::error::Error::unknown_field(field, expected_fields),
                field,
            )
        };

        match self.transport {
            EmailTransportKind::Blackhole => {}

            EmailTransportKind::Smtp => {
                if let Err(e) = Mailbox::from_str(&self.from) {
                    return Err(error_on_field(figment::error::Error::custom(e), "from").into());
                }

                if let Err(e) = Mailbox::from_str(&self.reply_to) {
                    return Err(error_on_field(figment::error::Error::custom(e), "reply_to").into());
                }

                match (self.username.is_some(), self.password.is_some()) {
                    (true, true) | (false, false) => {}
                    (true, false) => {
                        return Err(missing_field("password").into());
                    }
                    (false, true) => {
                        return Err(missing_field("username").into());
                    }
                }

                if self.mode.is_none() {
                    return Err(missing_field("mode").into());
                }

                if self.hostname.is_none() {
                    return Err(missing_field("hostname").into());
                }

                if self.command.is_some() {
                    return Err(unexpected_field(
                        "command",
                        &[
                            "from",
                            "reply_to",
                            "transport",
                            "mode",
                            "hostname",
                            "port",
                            "username",
                            "password",
                        ],
                    )
                    .into());
                }
            }

            EmailTransportKind::Sendmail => {
                let expected_fields = &["from", "reply_to", "transport", "command"];

                if let Err(e) = Mailbox::from_str(&self.from) {
                    return Err(error_on_field(figment::error::Error::custom(e), "from").into());
                }

                if let Err(e) = Mailbox::from_str(&self.reply_to) {
                    return Err(error_on_field(figment::error::Error::custom(e), "reply_to").into());
                }

                if self.command.is_none() {
                    return Err(missing_field("command").into());
                }

                if self.mode.is_some() {
                    return Err(unexpected_field("mode", expected_fields).into());
                }

                if self.hostname.is_some() {
                    return Err(unexpected_field("hostname", expected_fields).into());
                }

                if self.port.is_some() {
                    return Err(unexpected_field("port", expected_fields).into());
                }

                if self.username.is_some() {
                    return Err(unexpected_field("username", expected_fields).into());
                }

                if self.password.is_some() {
                    return Err(unexpected_field("password", expected_fields).into());
                }
            }
        }

        Ok(())
    }
}
