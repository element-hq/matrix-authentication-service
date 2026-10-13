// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Utility to build URLs

use ulid::Ulid;
use url::Url;

use crate::traits::Route;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlBuilder {
    http_base: Url,
    prefix: String,
    assets_base: String,
    issuer: Url,
}

impl UrlBuilder {
    /// Create an absolute URL for a route
    #[must_use]
    pub fn absolute_url_for<U>(&self, destination: &U) -> Url
    where
        U: Route,
    {
        destination.absolute_url(&self.http_base)
    }

    /// Create a relative URL for a route, prefixed with the base URL
    #[must_use]
    pub fn relative_url_for<U>(&self, destination: &U) -> String
    where
        U: Route,
    {
        format!(
            "{prefix}{destination}",
            prefix = self.prefix,
            destination = destination.path_and_query()
        )
    }

    /// The prefix added to all relative URLs
    #[must_use]
    pub fn prefix(&self) -> Option<&str> {
        if self.prefix.is_empty() {
            None
        } else {
            Some(&self.prefix)
        }
    }

    /// Create a (relative) redirect response to a route
    pub fn redirect<U>(&self, destination: &U) -> axum::response::Redirect
    where
        U: Route,
    {
        let uri = self.relative_url_for(destination);
        axum::response::Redirect::to(&uri)
    }

    /// Create an absolute redirect response to a route
    pub fn absolute_redirect<U>(&self, destination: &U) -> axum::response::Redirect
    where
        U: Route,
    {
        let uri = self.absolute_url_for(destination);
        axum::response::Redirect::to(uri.as_str())
    }

    /// Create a new [`UrlBuilder`] from a base URL
    ///
    /// # Panics
    ///
    /// Panics if the base URL contains a fragment, a query, credentials or
    /// isn't HTTP/HTTPS;
    #[must_use]
    pub fn new(base: Url, issuer: Option<Url>, assets_base: Option<String>) -> Self {
        assert!(
            base.scheme() == "http" || base.scheme() == "https",
            "base URL must be HTTP/HTTPS"
        );
        assert_eq!(base.query(), None, "base URL must not contain a query");
        assert_eq!(
            base.fragment(),
            None,
            "base URL must not contain a fragment"
        );
        assert_eq!(base.username(), "", "base URL must not contain credentials");
        assert_eq!(
            base.password(),
            None,
            "base URL must not contain credentials"
        );

        let issuer = issuer.unwrap_or_else(|| base.clone());
        let prefix = base.path().trim_end_matches('/').to_owned();
        let assets_base = assets_base.unwrap_or_else(|| format!("{prefix}/assets/"));
        Self {
            http_base: base,
            prefix,
            assets_base,
            issuer,
        }
    }

    /// Site public hostname
    ///
    /// # Panics
    ///
    /// Panics if the base URL does not have a host
    #[must_use]
    pub fn public_hostname(&self) -> &str {
        self.http_base
            .host_str()
            .expect("base URL must have a host")
    }

    /// HTTP base
    #[must_use]
    pub fn http_base(&self) -> Url {
        self.http_base.clone()
    }

    /// OIDC issuer
    #[must_use]
    pub fn oidc_issuer(&self) -> Url {
        self.issuer.clone()
    }

    /// OIDC discovery document URL
    #[must_use]
    pub fn oidc_discovery(&self) -> Url {
        crate::endpoints::OidcConfiguration.absolute_url(&self.issuer)
    }

    /// OAuth 2.0 authorization endpoint
    #[must_use]
    pub fn oauth_authorization_endpoint(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::OAuth2AuthorizationEndpoint)
    }

    /// OAuth 2.0 token endpoint
    #[must_use]
    pub fn oauth_token_endpoint(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::OAuth2TokenEndpoint)
    }

    /// OAuth 2.0 introspection endpoint
    #[must_use]
    pub fn oauth_introspection_endpoint(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::OAuth2Introspection)
    }

    /// OAuth 2.0 revocation endpoint
    #[must_use]
    pub fn oauth_revocation_endpoint(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::OAuth2Revocation)
    }

    /// OAuth 2.0 client registration endpoint
    #[must_use]
    pub fn oauth_registration_endpoint(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::OAuth2RegistrationEndpoint)
    }

    /// OAuth 2.0 device authorization endpoint
    #[must_use]
    pub fn oauth_device_authorization_endpoint(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::OAuth2DeviceAuthorizationEndpoint)
    }

    /// OAuth 2.0 device code link
    #[must_use]
    pub fn device_code_link(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::DeviceCodeLink::default())
    }

    /// OAuth 2.0 device code link full URL
    #[must_use]
    pub fn device_code_link_full(&self, code: String) -> Url {
        self.absolute_url_for(&crate::endpoints::DeviceCodeLink::with_code(code))
    }

    // OIDC userinfo endpoint
    #[must_use]
    pub fn oidc_userinfo_endpoint(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::OidcUserinfo)
    }

    /// JWKS URI
    #[must_use]
    pub fn jwks_uri(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::OAuth2Keys)
    }

    /// Static asset
    #[must_use]
    pub fn static_asset(&self, path: String) -> Url {
        self.absolute_url_for(&crate::endpoints::StaticAsset::new(path))
    }

    /// Static asset base
    #[must_use]
    pub fn assets_base(&self) -> &str {
        &self.assets_base
    }

    /// GraphQL endpoint
    #[must_use]
    pub fn graphql_endpoint(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::GraphQL)
    }

    /// Upstream redirect URI
    #[must_use]
    pub fn upstream_oauth_callback(&self, id: Ulid) -> Url {
        self.absolute_url_for(&crate::endpoints::UpstreamOAuth2Callback::new(id))
    }

    /// Upstream authorize URI
    #[must_use]
    pub fn upstream_oauth_authorize(&self, id: Ulid) -> Url {
        self.absolute_url_for(&crate::endpoints::UpstreamOAuth2Authorize::new(id))
    }

    /// Account management URI
    #[must_use]
    pub fn account_management_uri(&self) -> Url {
        self.absolute_url_for(&crate::endpoints::Account::default())
    }

    /// Account recovery link
    #[must_use]
    pub fn account_recovery_link(&self, ticket: String) -> Url {
        self.absolute_url_for(&crate::endpoints::AccountRecoveryFinish::new(ticket))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[should_panic(expected = "base URL must be HTTP/HTTPS")]
    fn test_invalid_base_url_scheme() {
        let _ = super::UrlBuilder::new(url::Url::parse("file:///tmp/").unwrap(), None, None);
    }

    #[test]
    #[should_panic(expected = "base URL must not contain a query")]
    fn test_invalid_base_url_query() {
        let _ = super::UrlBuilder::new(
            url::Url::parse("https://example.com/?foo=bar").unwrap(),
            None,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "base URL must not contain a fragment")]
    fn test_invalid_base_url_fragment() {
        let _ = super::UrlBuilder::new(
            url::Url::parse("https://example.com/#foo").unwrap(),
            None,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "base URL must not contain credentials")]
    fn test_invalid_base_url_credentials() {
        let _ = super::UrlBuilder::new(
            url::Url::parse("https://foo@example.com/").unwrap(),
            None,
            None,
        );
    }

    #[test]
    fn test_url_prefix() {
        let builder = super::UrlBuilder::new(
            url::Url::parse("https://example.com/foo/").unwrap(),
            None,
            None,
        );
        assert_eq!(builder.prefix, "/foo");

        let builder =
            super::UrlBuilder::new(url::Url::parse("https://example.com/").unwrap(), None, None);
        assert_eq!(builder.prefix, "");
    }

    #[test]
    fn test_absolute_uri_prefix() {
        let builder = super::UrlBuilder::new(
            url::Url::parse("https://example.com/foo/").unwrap(),
            None,
            None,
        );

        let uri = builder.absolute_url_for(&crate::endpoints::OAuth2AuthorizationEndpoint);
        assert_eq!(uri.as_str(), "https://example.com/foo/authorize");
    }
}
