// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Types for provider discovery using [Webfinger].
//!
//! [Webfinger]: https://www.rfc-editor.org/rfc/rfc7033

use serde::{Deserialize, Serialize};
use url::Url;

/// The response of the Webfinger endpoint.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct WebFingerResponse {
    /// A URI that identifies the entity described by the response.
    subject: String,

    /// Links that describe the subject.
    links: Vec<WebFingerLink>,
}

impl WebFingerResponse {
    /// Creates a new `WebFingerResponse` with the given subject.
    #[must_use]
    pub const fn new(subject: String) -> Self {
        Self {
            subject,
            links: Vec::new(),
        }
    }

    /// Adds the given link to this `WebFingerResponse`.
    #[must_use]
    pub fn with_link(mut self, link: WebFingerLink) -> Self {
        self.links.push(link);
        self
    }

    /// Adds the given issuer to this `WebFingerResponse`.
    #[must_use]
    pub fn with_issuer(self, issuer: Url) -> Self {
        self.with_link(WebFingerLink::issuer(issuer))
    }
}

/// A link in a Webfinger response.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "rel")]
pub enum WebFingerLink {
    /// An OpenID Connect issuer.
    #[serde(rename = "http://openid.net/specs/connect/1.0/issuer")]
    OidcIssuer {
        /// The URL of the issuer.
        href: Url,
    },
}

impl WebFingerLink {
    /// Creates a new `WebFingerLink` for an OpenID Connect issuer.
    #[must_use]
    pub const fn issuer(href: Url) -> Self {
        Self::OidcIssuer { href }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn serialize_webfinger_response_test() {
        let res = WebFingerResponse::new("acct:john@example.com".to_owned())
            .with_issuer(Url::parse("https://account.example.com/").unwrap());

        let res = serde_json::to_value(res).unwrap();

        assert_eq!(
            res,
            json!({
                "subject": "acct:john@example.com",
                "links": [{
                    "rel": "http://openid.net/specs/connect/1.0/issuer",
                    "href": "https://account.example.com/",
                }]
            })
        );
    }
}
