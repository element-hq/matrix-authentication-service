// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

pub(crate) mod endpoints;
pub(crate) mod traits;
mod url_builder;

pub use self::{endpoints::*, traits::Route, url_builder::UrlBuilder};

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use ulid::Ulid;
    use url::Url;

    use super::*;

    #[test]
    fn test_relative_urls() {
        assert_eq!(
            OidcConfiguration.path_and_query(),
            Cow::Borrowed("/.well-known/openid-configuration")
        );
        assert_eq!(Index.path_and_query(), Cow::Borrowed("/"));
        assert_eq!(
            Login::and_continue_grant(Ulid::nil()).path_and_query(),
            Cow::Borrowed("/login?kind=continue_authorization_grant&id=00000000000000000000000000")
        );
    }

    #[test]
    fn test_register_urls() {
        assert_eq!(
            Register::default().path_and_query(),
            Cow::Borrowed("/register")
        );
        assert_eq!(
            Register::default()
                .with_token("a token&more".to_owned())
                .path_and_query(),
            Cow::Borrowed("/register?token=a+token%26more")
        );
        assert_eq!(
            Register::and_continue_grant(Ulid::nil())
                .with_token("invite".to_owned())
                .path_and_query(),
            Cow::Borrowed(
                "/register?token=invite&kind=continue_authorization_grant&id=00000000000000000000000000"
            )
        );
    }

    #[test]
    fn test_absolute_urls() {
        let base = Url::try_from("https://example.com/").unwrap();
        assert_eq!(Index.absolute_url(&base).as_str(), "https://example.com/");
        assert_eq!(
            OidcConfiguration.absolute_url(&base).as_str(),
            "https://example.com/.well-known/openid-configuration"
        );
    }
}
