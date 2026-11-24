// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! `Content-Security-Policy` header values.
//!
//! None of the policies for HTML pages set `form-action`: Chromium and Safari
//! enforce it on every redirect following a form submission, and most forms
//! here end in a redirect to another origin.

use http::HeaderValue;
use mas_data_model::{CaptchaConfig, CaptchaService};
use mas_router::UrlBuilder;
use url::{Host, Url};

/// For responses which are not HTML pages: JSON, assets, plain redirects.
pub const LOCKED_DOWN: HeaderValue = HeaderValue::from_static(
    "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
);

/// For the server-rendered pages. `worker-src` falls back to `script-src`, not
/// to `default-src`, and `img-src https:` covers hot-linked client logos.
pub const SERVER_RENDERED: HeaderValue = HeaderValue::from_static(
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' https:; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'",
);

/// The third-party sources a captcha provider's SDK loads.
struct CaptchaSources {
    script: &'static [&'static str],
    style: &'static [&'static str],
    connect: &'static [&'static str],
    frame: &'static [&'static str],
}

const NO_CAPTCHA: CaptchaSources = CaptchaSources {
    script: &[],
    style: &[],
    connect: &[],
    frame: &[],
};

// The SDK is loaded from `recaptcha.net`, but falls back to the `google.com`
// origins listed in Google's CSP guidance.
const RECAPTCHA: CaptchaSources = CaptchaSources {
    script: &[
        "https://www.recaptcha.net/recaptcha/",
        "https://www.google.com/recaptcha/",
        "https://www.gstatic.com/recaptcha/",
    ],
    style: &[],
    connect: &[
        "https://www.recaptcha.net/recaptcha/",
        "https://www.google.com/recaptcha/",
    ],
    frame: &[
        "https://www.recaptcha.net/recaptcha/",
        "https://www.google.com/recaptcha/",
        "https://recaptcha.google.com/recaptcha/",
    ],
};

const TURNSTILE: CaptchaSources = CaptchaSources {
    script: &["https://challenges.cloudflare.com"],
    style: &[],
    connect: &[],
    frame: &["https://challenges.cloudflare.com"],
};

// A `*.` source does not match the apex, and the SDK uses both.
const HCAPTCHA_ORIGINS: &[&str] = &["https://hcaptcha.com/", "https://*.hcaptcha.com/"];
const HCAPTCHA: CaptchaSources = CaptchaSources {
    script: HCAPTCHA_ORIGINS,
    style: HCAPTCHA_ORIGINS,
    connect: HCAPTCHA_ORIGINS,
    frame: HCAPTCHA_ORIGINS,
};

/// For the registration page. `captcha` is the captcha the page renders, if
/// any.
#[must_use]
pub fn register(captcha: Option<&CaptchaConfig>) -> HeaderValue {
    let sources = match captcha.map(|captcha| captcha.service) {
        None => &NO_CAPTCHA,
        Some(CaptchaService::RecaptchaV2) => &RECAPTCHA,
        Some(CaptchaService::CloudflareTurnstile) => &TURNSTILE,
        Some(CaptchaService::HCaptcha) => &HCAPTCHA,
    };

    let frame_src = if sources.frame.is_empty() {
        String::new()
    } else {
        format!("frame-src {}; ", sources.frame.join(" "))
    };

    header(format!(
        "default-src 'none'; script-src 'self'{script}; style-src 'self'{style}; font-src 'self'; img-src 'self' https:; connect-src 'self'{connect}; {frame_src}worker-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        script = extra(sources.script),
        style = extra(sources.style),
        connect = extra(sources.connect),
    ))
}

/// For the account SPA shell, which can frame the plan management page.
#[must_use]
pub fn app(plan_management_iframe_uri: Option<&str>, url_builder: &UrlBuilder) -> HeaderValue {
    let base = url_builder.http_base();
    let frame_src = plan_management_iframe_uri
        .and_then(|uri| base.join(uri).ok())
        .and_then(|url| {
            if url.origin() == base.origin() {
                Some("'self'".to_owned())
            } else {
                host_source(&url)
            }
        })
        .map_or_default(|source| format!("frame-src {source}; "));

    header(format!(
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' https: data:; connect-src 'self'; {frame_src}worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    ))
}

/// For the Swagger UI pages. The admin API may be served on another listener
/// than the public one, while the page fetches from the public base URL.
#[must_use]
pub fn swagger(url_builder: &UrlBuilder) -> HeaderValue {
    let public =
        host_source(&url_builder.http_base()).map_or_default(|source| format!(" {source}"));

    header(format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; connect-src 'self'{public}; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    ))
}

/// The origin of a URL as a CSP host-source, if the grammar can express it:
/// hosts are dot-separated `[A-Za-z0-9-]` labels or IPv4 addresses.
fn host_source(url: &Url) -> Option<String> {
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }

    let expressible = match url.host()? {
        Host::Ipv4(_) => true,
        Host::Ipv6(_) => false,
        Host::Domain(domain) => domain.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }),
    };

    expressible.then(|| url.origin().ascii_serialization())
}

fn extra(sources: &[&str]) -> String {
    sources.iter().flat_map(|source| [" ", source]).collect()
}

fn header(policy: String) -> HeaderValue {
    HeaderValue::try_from(policy).expect("policy is a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url_builder(base: &str) -> UrlBuilder {
        UrlBuilder::new(base.parse().unwrap(), None, None)
    }

    fn captcha(service: CaptchaService) -> CaptchaConfig {
        CaptchaConfig {
            service,
            site_key: "site".to_owned(),
            secret_key: "secret".to_owned(),
        }
    }

    #[test]
    fn test_register() {
        assert_eq!(
            register(None),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' https:; connect-src 'self'; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        );

        assert_eq!(
            register(Some(&captcha(CaptchaService::RecaptchaV2))),
            "default-src 'none'; script-src 'self' https://www.recaptcha.net/recaptcha/ https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; style-src 'self'; font-src 'self'; img-src 'self' https:; connect-src 'self' https://www.recaptcha.net/recaptcha/ https://www.google.com/recaptcha/; frame-src https://www.recaptcha.net/recaptcha/ https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        );

        assert_eq!(
            register(Some(&captcha(CaptchaService::CloudflareTurnstile))),
            "default-src 'none'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; font-src 'self'; img-src 'self' https:; connect-src 'self'; frame-src https://challenges.cloudflare.com; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        );

        assert_eq!(
            register(Some(&captcha(CaptchaService::HCaptcha))),
            "default-src 'none'; script-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; style-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; font-src 'self'; img-src 'self' https:; connect-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; frame-src https://hcaptcha.com/ https://*.hcaptcha.com/; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        );
    }

    #[test]
    fn test_app() {
        let url_builder = url_builder("https://example.com/auth/");
        let with_frame = |frame_src: &str| {
            format!(
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' https: data:; connect-src 'self'; {frame_src}worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            )
        };

        assert_eq!(app(None, &url_builder), with_frame("").as_str());
        assert_eq!(
            app(Some("/plan"), &url_builder),
            with_frame("frame-src 'self'; ").as_str()
        );
        assert_eq!(
            app(Some("https://plan.example.org:8443/iframe"), &url_builder),
            with_frame("frame-src https://plan.example.org:8443; ").as_str()
        );
        assert_eq!(
            app(Some("http://[::1]:8080/plan"), &url_builder),
            with_frame("").as_str()
        );
        assert_eq!(
            app(Some("data:text/html,hello"), &url_builder),
            with_frame("").as_str()
        );
    }

    #[test]
    fn test_swagger() {
        assert_eq!(
            swagger(&url_builder("https://example.com/")),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; connect-src 'self' https://example.com; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        );

        assert_eq!(
            swagger(&url_builder("http://[::]:8080/")),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; worker-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        );
    }

    #[test]
    fn test_host_source() {
        let source = |url: &str| host_source(&Url::parse(url).unwrap());

        assert_eq!(
            source("https://example.com/path?query").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            source("https://example.com:443/").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            source("http://my-host.example:8080/").as_deref(),
            Some("http://my-host.example:8080")
        );
        assert_eq!(
            source("http://127.0.0.1:8080/").as_deref(),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(source("http://[::1]:8080/"), None);
        assert_eq!(source("https://under_score.example.com/"), None);
        assert_eq!(source("ftp://example.com/"), None);
        assert_eq!(source("com.example.app:/callback"), None);
    }
}
