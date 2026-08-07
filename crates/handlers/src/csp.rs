// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Per-route-class `Content-Security-Policy` headers.
//!
//! The policies are computed once at startup from the site configuration and
//! the [`UrlBuilder`], and stored as prebuilt [`HeaderValue`]s. The only
//! per-response policy is the one for the `form_post` authorization response,
//! whose `form-action` depends on the client's redirect URI.

use http::HeaderValue;
use mas_data_model::{CaptchaService, SiteConfig};
use mas_router::UrlBuilder;
use url::Url;

/// The third-party sources a captcha provider needs.
#[derive(Default, Clone, Copy)]
struct CaptchaSources {
    script: &'static [&'static str],
    style: &'static [&'static str],
    connect: &'static [&'static str],
    frame: &'static [&'static str],
}

impl CaptchaSources {
    fn for_service(service: CaptchaService) -> Self {
        match service {
            CaptchaService::RecaptchaV2 => Self {
                script: &[
                    "https://www.recaptcha.net/recaptcha/",
                    "https://www.gstatic.com/recaptcha/",
                ],
                style: &[],
                connect: &[],
                frame: &["https://www.recaptcha.net/"],
            },
            CaptchaService::CloudflareTurnstile => Self {
                script: &["https://challenges.cloudflare.com/turnstile/v0/"],
                style: &[],
                connect: &["https://challenges.cloudflare.com/"],
                frame: &["https://challenges.cloudflare.com/"],
            },
            CaptchaService::HCaptcha => Self {
                script: &["https://js.hcaptcha.com/", "https://*.hcaptcha.com/"],
                style: &["https://hcaptcha.com/", "https://*.hcaptcha.com/"],
                connect: &["https://hcaptcha.com/", "https://*.hcaptcha.com/"],
                frame: &["https://newassets.hcaptcha.com/"],
            },
        }
    }
}

/// A list of directives, serialized to a policy string.
///
/// Directives with an empty source list are omitted: `default-src 'none'`
/// already covers them.
#[derive(Default)]
struct Policy {
    directives: Vec<(&'static str, Vec<String>)>,
}

impl Policy {
    fn directive(mut self, name: &'static str, sources: Vec<String>) -> Self {
        if !sources.is_empty() {
            self.directives.push((name, sources));
        }
        self
    }

    fn finish(self) -> String {
        self.directives
            .into_iter()
            .map(|(name, sources)| format!("{name} {}", sources.join(" ")))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn finish_header(self) -> HeaderValue {
        HeaderValue::try_from(self.finish()).expect("policy is a valid header value")
    }
}

/// Concatenate source expression lists.
fn sources(parts: &[&[&str]]) -> Vec<String> {
    parts
        .iter()
        .flat_map(|part| part.iter())
        .map(|source| (*source).to_owned())
        .collect()
}

/// The assets origin, when assets are served from another origin than the
/// public base URL. Same-origin assets are covered by `'self'`.
fn assets_origin(url_builder: &UrlBuilder) -> Option<String> {
    let assets = Url::parse(url_builder.assets_base()).ok()?;
    let origin = assets.origin();
    if !origin.is_tuple() || origin == url_builder.http_base().origin() {
        return None;
    }

    Some(origin.ascii_serialization())
}

/// The `frame-src` source for the plan-management iframe.
///
/// That URI is passed through from the configuration without validation, so
/// fall back to using it as-is when it isn't a parseable URL — worst case the
/// iframe gets blocked, which is the safe failure.
fn plan_iframe_source(uri: &str) -> Option<String> {
    if let Ok(url) = Url::parse(uri) {
        let origin = url.origin();
        if origin.is_tuple() {
            return Some(origin.ascii_serialization());
        }
    }

    // A source expression with whitespace, a semicolon or a comma in it would
    // inject further directives into the header
    if uri.is_empty()
        || !uri.is_ascii()
        || uri
            .bytes()
            .any(|b| b <= b' ' || b == b';' || b == b',' || b == b'\x7f')
    {
        tracing::warn!(
            plan_management_iframe_uri = uri,
            "Plan management iframe URI is not a valid URL and can't be used as a Content-Security-Policy source; the iframe will be blocked"
        );
        return None;
    }

    tracing::warn!(
        plan_management_iframe_uri = uri,
        "Plan management iframe URI is not a valid URL; using it as-is as a Content-Security-Policy source"
    );
    Some(uri.to_owned())
}

/// The `form-action` source for a client redirect URI.
fn form_action_source(redirect_uri: &Url) -> String {
    match redirect_uri.scheme() {
        "http" | "https" => redirect_uri.origin().ascii_serialization(),
        // Native clients use custom schemes, which have an opaque origin
        scheme => format!("{scheme}:"),
    }
}

/// The `Content-Security-Policy` headers served by each route class.
#[derive(Clone)]
pub struct Csp {
    /// Class A: server-rendered human-facing pages.
    human: HeaderValue,

    /// Class C: the account SPA shell.
    app: HeaderValue,

    /// Class D: the Swagger UI pages.
    swagger: HeaderValue,

    /// Class E: machine endpoints, and the catch-all for everything else.
    api: HeaderValue,

    /// Class B: everything but the `form-action` directive, which depends on
    /// the redirect URI of the grant being completed.
    form_post_base: String,
}

impl Csp {
    /// Build the policies for a deployment.
    #[must_use]
    pub fn new(site_config: &SiteConfig, url_builder: &UrlBuilder) -> Self {
        let assets = assets_origin(url_builder);
        let assets: Vec<&str> = assets.as_deref().into_iter().collect();
        let assets = assets.as_slice();

        let captcha = site_config
            .captcha
            .as_ref()
            .map(|captcha| CaptchaSources::for_service(captcha.service))
            .unwrap_or_default();

        let plan_iframe = site_config
            .plan_management_iframe_uri
            .as_deref()
            .and_then(plan_iframe_source);
        let plan_iframe: Vec<&str> = plan_iframe.as_deref().into_iter().collect();

        let human = Policy::default()
            .directive("default-src", sources(&[&["'none'"]]))
            .directive(
                "script-src",
                sources(&[&["'self'"], assets, captcha.script]),
            )
            .directive("style-src", sources(&[&["'self'"], assets, captcha.style]))
            .directive("font-src", sources(&[&["'self'"], assets]))
            .directive("img-src", sources(&[&["'self'"], assets, &["https:"]]))
            .directive("connect-src", sources(&[&["'self'"], captcha.connect]))
            .directive("frame-src", sources(&[captcha.frame]))
            .directive("form-action", sources(&[&["'self'"]]))
            .directive("frame-ancestors", sources(&[&["'none'"]]))
            .directive("base-uri", sources(&[&["'none'"]]))
            .directive("object-src", sources(&[&["'none'"]]))
            .finish_header();

        let app = Policy::default()
            .directive("default-src", sources(&[&["'none'"]]))
            .directive("script-src", sources(&[&["'self'"], assets]))
            // `'unsafe-inline'` is a temporary concession for vaul's top-level
            // `<style>` injection — see plans/csp.md §4.3 and §8.5
            .directive(
                "style-src",
                sources(&[&["'self'"], assets, &["'unsafe-inline'"]]),
            )
            .directive("font-src", sources(&[&["'self'"], assets]))
            .directive(
                "img-src",
                sources(&[&["'self'"], assets, &["https:", "data:"]]),
            )
            .directive("connect-src", sources(&[&["'self'"], assets]))
            .directive("frame-src", sources(&[plan_iframe.as_slice()]))
            .directive("form-action", sources(&[&["'self'"]]))
            .directive("frame-ancestors", sources(&[&["'none'"]]))
            .directive("base-uri", sources(&[&["'none'"]]))
            .directive("object-src", sources(&[&["'none'"]]))
            .finish_header();

        let swagger = Policy::default()
            .directive("default-src", sources(&[&["'none'"]]))
            .directive("script-src", sources(&[&["'self'"], assets]))
            .directive("style-src", sources(&[&["'self'"], assets]))
            .directive("font-src", sources(&[&["'self'"], assets]))
            .directive(
                "img-src",
                sources(&[&["'self'"], assets, &["data:", "blob:"]]),
            )
            .directive("connect-src", sources(&[&["'self'"]]))
            .directive("form-action", sources(&[&["'self'"]]))
            .directive("frame-ancestors", sources(&[&["'none'"]]))
            .directive("base-uri", sources(&[&["'none'"]]))
            .directive("object-src", sources(&[&["'none'"]]))
            .finish_header();

        let api = Policy::default()
            .directive("default-src", sources(&[&["'none'"]]))
            .directive("frame-ancestors", sources(&[&["'none'"]]))
            .finish_header();

        let form_post_base = Policy::default()
            .directive("default-src", sources(&[&["'none'"]]))
            .directive("script-src", sources(&[&["'self'"], assets]))
            .directive("style-src", sources(&[&["'self'"], assets]))
            .directive("font-src", sources(&[&["'self'"], assets]))
            .directive("img-src", sources(&[&["'self'"], assets, &["https:"]]))
            .directive("connect-src", sources(&[&["'self'"]]))
            .directive("frame-ancestors", sources(&[&["'none'"]]))
            .directive("base-uri", sources(&[&["'none'"]]))
            .directive("object-src", sources(&[&["'none'"]]))
            .finish();

        Self {
            human,
            app,
            swagger,
            api,
            form_post_base,
        }
    }

    /// Class A: server-rendered human-facing pages.
    #[must_use]
    pub fn human(&self) -> HeaderValue {
        self.human.clone()
    }

    /// Class C: the account SPA shell.
    #[must_use]
    pub fn app(&self) -> HeaderValue {
        self.app.clone()
    }

    /// Class D: the Swagger UI pages.
    #[must_use]
    pub fn swagger(&self) -> HeaderValue {
        self.swagger.clone()
    }

    /// Class E: machine endpoints, and the catch-all for everything else.
    #[must_use]
    pub fn api(&self) -> HeaderValue {
        self.api.clone()
    }

    /// Class B: the `form_post` authorization response, which auto-submits a
    /// form to the client's redirect URI.
    #[must_use]
    pub fn form_post(&self, redirect_uri: &Url) -> HeaderValue {
        let source = form_action_source(redirect_uri);
        HeaderValue::try_from(format!("{}; form-action {source}", self.form_post_base)).unwrap_or_else(
            |_| {
                tracing::warn!(
                    %redirect_uri,
                    "Could not build a Content-Security-Policy header for the form_post response; blocking the form submission instead"
                );
                HeaderValue::from_static("default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
            },
        )
    }
}

impl Default for Csp {
    /// The most restrictive policy for every class.
    ///
    /// Only for contexts which have no deployment configuration at hand, such
    /// as the API schema generator.
    fn default() -> Self {
        let api = Policy::default()
            .directive("default-src", sources(&[&["'none'"]]))
            .directive("frame-ancestors", sources(&[&["'none'"]]))
            .finish();

        Self {
            human: HeaderValue::try_from(api.clone()).expect("policy is a valid header value"),
            app: HeaderValue::try_from(api.clone()).expect("policy is a valid header value"),
            swagger: HeaderValue::try_from(api.clone()).expect("policy is a valid header value"),
            api: HeaderValue::try_from(api.clone()).expect("policy is a valid header value"),
            form_post_base: api,
        }
    }
}

#[cfg(test)]
mod tests {
    use mas_data_model::{CaptchaConfig, CaptchaService, SiteConfig};
    use mas_router::UrlBuilder;

    use super::Csp;
    use crate::test_utils::test_site_config;

    fn site_config(
        captcha: Option<CaptchaService>,
        plan_management_iframe_uri: Option<&str>,
    ) -> SiteConfig {
        SiteConfig {
            captcha: captcha.map(|service| CaptchaConfig {
                service,
                site_key: "site-key".to_owned(),
                secret_key: "secret-key".to_owned(),
            }),
            plan_management_iframe_uri: plan_management_iframe_uri.map(ToOwned::to_owned),
            ..test_site_config()
        }
    }

    fn url_builder(assets_base: Option<&str>) -> UrlBuilder {
        UrlBuilder::new(
            "https://example.com/".parse().unwrap(),
            None,
            assets_base.map(ToOwned::to_owned),
        )
    }

    #[test]
    fn test_no_captcha_no_iframe_same_origin_assets() {
        let csp = Csp::new(&site_config(None, None), &url_builder(None));

        assert_eq!(
            csp.human(),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(
            csp.app(),
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             font-src 'self'; img-src 'self' https: data:; connect-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(
            csp.swagger(),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' data: blob:; connect-src 'self'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(csp.api(), "default-src 'none'; frame-ancestors 'none'");
    }

    #[test]
    fn test_cross_origin_assets() {
        let csp = Csp::new(
            &site_config(None, None),
            &url_builder(Some("https://cdn.example.com/assets/")),
        );

        assert_eq!(
            csp.human(),
            "default-src 'none'; script-src 'self' https://cdn.example.com; \
             style-src 'self' https://cdn.example.com; font-src 'self' https://cdn.example.com; \
             img-src 'self' https://cdn.example.com https:; connect-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(
            csp.app(),
            "default-src 'none'; script-src 'self' https://cdn.example.com; \
             style-src 'self' https://cdn.example.com 'unsafe-inline'; \
             font-src 'self' https://cdn.example.com; \
             img-src 'self' https://cdn.example.com https: data:; \
             connect-src 'self' https://cdn.example.com; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(
            csp.swagger(),
            "default-src 'none'; script-src 'self' https://cdn.example.com; \
             style-src 'self' https://cdn.example.com; font-src 'self' https://cdn.example.com; \
             img-src 'self' https://cdn.example.com data: blob:; connect-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(csp.api(), "default-src 'none'; frame-ancestors 'none'");
    }

    /// An absolute assets base on the same origin as the public base URL folds
    /// into `'self'`
    #[test]
    fn test_same_origin_absolute_assets() {
        let csp = Csp::new(
            &site_config(None, None),
            &url_builder(Some("https://example.com/assets/")),
        );

        assert_eq!(
            csp.human(),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    #[test]
    fn test_recaptcha() {
        let csp = Csp::new(
            &site_config(Some(CaptchaService::RecaptchaV2), None),
            &url_builder(None),
        );

        assert_eq!(
            csp.human(),
            "default-src 'none'; \
             script-src 'self' https://www.recaptcha.net/recaptcha/ https://www.gstatic.com/recaptcha/; \
             style-src 'self'; font-src 'self'; img-src 'self' https:; connect-src 'self'; \
             frame-src https://www.recaptcha.net/; form-action 'self'; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'"
        );

        // The SPA shell and the API never load a captcha
        assert_eq!(
            csp.app(),
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             font-src 'self'; img-src 'self' https: data:; connect-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    #[test]
    fn test_turnstile() {
        let csp = Csp::new(
            &site_config(Some(CaptchaService::CloudflareTurnstile), None),
            &url_builder(None),
        );

        assert_eq!(
            csp.human(),
            "default-src 'none'; \
             script-src 'self' https://challenges.cloudflare.com/turnstile/v0/; \
             style-src 'self'; font-src 'self'; img-src 'self' https:; \
             connect-src 'self' https://challenges.cloudflare.com/; \
             frame-src https://challenges.cloudflare.com/; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    #[test]
    fn test_hcaptcha() {
        let csp = Csp::new(
            &site_config(Some(CaptchaService::HCaptcha), None),
            &url_builder(None),
        );

        assert_eq!(
            csp.human(),
            "default-src 'none'; \
             script-src 'self' https://js.hcaptcha.com/ https://*.hcaptcha.com/; \
             style-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; \
             font-src 'self'; img-src 'self' https:; \
             connect-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; \
             frame-src https://newassets.hcaptcha.com/; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    #[test]
    fn test_plan_management_iframe() {
        let csp = Csp::new(
            &site_config(None, Some("https://plan.example.com/embed?foo=bar")),
            &url_builder(None),
        );

        assert_eq!(
            csp.app(),
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             font-src 'self'; img-src 'self' https: data:; connect-src 'self'; \
             frame-src https://plan.example.com; form-action 'self'; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'"
        );

        // Only the SPA shell embeds it
        assert_eq!(
            csp.human(),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    /// An unparseable iframe URI is emitted as-is, but one which would inject
    /// further directives is dropped
    #[test]
    fn test_invalid_plan_management_iframe() {
        let csp = Csp::new(
            &site_config(None, Some("plan.example.com")),
            &url_builder(None),
        );
        assert_eq!(
            csp.app(),
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             font-src 'self'; img-src 'self' https: data:; connect-src 'self'; \
             frame-src plan.example.com; form-action 'self'; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'"
        );

        let csp = Csp::new(
            &site_config(None, Some("plan.example.com; script-src *")),
            &url_builder(None),
        );
        assert_eq!(
            csp.app(),
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             font-src 'self'; img-src 'self' https: data:; connect-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    #[test]
    fn test_form_post() {
        let csp = Csp::new(
            &site_config(Some(CaptchaService::HCaptcha), None),
            &url_builder(None),
        );

        // The captcha sources are not in the form_post policy
        assert_eq!(
            csp.form_post(
                &"https://client.example.com/callback?foo=bar"
                    .parse()
                    .unwrap()
            ),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'; form-action https://client.example.com"
        );

        // A non-default port is part of the origin
        assert_eq!(
            csp.form_post(&"http://localhost:8080/callback".parse().unwrap()),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'; form-action http://localhost:8080"
        );

        // Native clients use custom schemes, which have an opaque origin
        assert_eq!(
            csp.form_post(&"com.example.app:/callback".parse().unwrap()),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'; form-action com.example.app:"
        );
    }

    #[test]
    fn test_form_post_with_cross_origin_assets() {
        let csp = Csp::new(
            &site_config(None, None),
            &url_builder(Some("https://cdn.example.com/assets/")),
        );

        assert_eq!(
            csp.form_post(&"https://client.example.com/callback".parse().unwrap()),
            "default-src 'none'; script-src 'self' https://cdn.example.com; \
             style-src 'self' https://cdn.example.com; font-src 'self' https://cdn.example.com; \
             img-src 'self' https://cdn.example.com https:; connect-src 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'; \
             form-action https://client.example.com"
        );
    }
}
