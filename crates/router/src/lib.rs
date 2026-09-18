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
    fn test_login_method_hint_in_urls() {
        let provider_id = Ulid::from_string("01HFRQFT5QFMJFGF01P7JAV2ME").unwrap();

        // An empty `Register` must not grow a stray question mark
        assert_eq!(
            Register::default().path_and_query(),
            Cow::Borrowed("/register")
        );

        let login = Login::and_continue_grant(Ulid::nil())
            .with_login_method(LoginMethodHint::UpstreamOAuth2(provider_id));
        assert_eq!(
            login.path_and_query(),
            Cow::Borrowed(
                "/login?kind=continue_authorization_grant&id=00000000000000000000000000\
                 &io.element.login_method=upstream-oauth2%3A01HFRQFT5QFMJFGF01P7JAV2ME"
            )
        );
        let parsed: Login =
            serde_urlencoded::from_str(login.path_and_query().split_once('?').unwrap().1).unwrap();
        assert_eq!(parsed.path_and_query(), login.path_and_query());

        let register =
            Register::and_continue_grant(Ulid::nil()).with_login_method(LoginMethodHint::Password);
        assert_eq!(
            register.path_and_query(),
            Cow::Borrowed(
                "/register?kind=continue_authorization_grant&id=00000000000000000000000000\
                 &io.element.login_method=password"
            )
        );
        let parsed: Register =
            serde_urlencoded::from_str(register.path_and_query().split_once('?').unwrap().1)
                .unwrap();
        assert_eq!(parsed.path_and_query(), register.path_and_query());
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
