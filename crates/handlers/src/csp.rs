// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Per-route `Content-Security-Policy` headers.
//!
//! Each kind of route MAS serves gets the strictest policy it can bear, rather
//! than one lowest-common-denominator policy: server-rendered pages, the
//! account SPA shell, the Swagger UI, and everything else. The policies are
//! computed once at startup from the site configuration and the [`UrlBuilder`],
//! and stored as prebuilt [`HeaderValue`]s.
//!
//! The exceptions are the pages which hand the authorization response back to
//! the client by posting a form to its redirect URI: their `form-action` names
//! that URI, so it is built per response.

use std::{borrow::Cow, fmt, sync::Arc};

use http::HeaderValue;
use indexmap::IndexMap;
use mas_data_model::{CaptchaService, SiteConfig};
use mas_router::UrlBuilder;
use url::{Host, Origin, Url};

/// A source expression: what a directive allows.
///
/// Building one is the only way to get a source into a policy, so a policy
/// can't end up carrying something a browser would fail to parse and drop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// `'none'`
    Nothing,

    /// `'self'`
    SameOrigin,

    /// `'unsafe-inline'`
    UnsafeInline,

    /// Any URL with this scheme, like `https:`
    Scheme(Cow<'static, str>),

    /// One origin, or a vendor's documented URL prefix
    Url(Cow<'static, str>),
}

impl Source {
    /// Any URL with the given scheme.
    fn scheme(scheme: impl Into<Cow<'static, str>>) -> Self {
        Self::Scheme(scheme.into())
    }

    /// A vendor's documented URL prefix.
    fn url(url: &'static str) -> Self {
        Self::Url(Cow::Borrowed(url))
    }

    /// One origin, if a source expression can name it at all.
    ///
    /// A host is `ALPHA / DIGIT / "-"` separated by dots and nothing else, so
    /// an IPv6 literal — which loopback redirect URIs are allowed to use — has
    /// no representation, and neither does a domain with an underscore in it.
    /// A browser drops a source expression it can't parse, so emitting one is
    /// worse than emitting nothing.
    fn origin(origin: &Origin) -> Option<Self> {
        let Origin::Tuple(_, host, _) = origin else {
            return None;
        };

        let nameable = match host {
            Host::Ipv4(_) => true,
            Host::Ipv6(_) => false,
            Host::Domain(domain) => domain.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
        };

        nameable.then(|| Self::Url(Cow::Owned(origin.ascii_serialization())))
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nothing => f.write_str("'none'"),
            Self::SameOrigin => f.write_str("'self'"),
            Self::UnsafeInline => f.write_str("'unsafe-inline'"),
            Self::Scheme(scheme) => write!(f, "{scheme}:"),
            Self::Url(url) => f.write_str(url),
        }
    }
}

/// The third-party sources a captcha provider needs.
#[derive(Default, Clone)]
struct CaptchaSources {
    script: Vec<Source>,
    style: Vec<Source>,
    connect: Vec<Source>,
    frame: Vec<Source>,
}

impl CaptchaSources {
    fn for_service(service: CaptchaService) -> Self {
        match service {
            // MAS loads the SDK from the `recaptcha.net` alias, but the SDK
            // itself falls back to the `google.com` origins Google's own CSP
            // guidance lists, so both are allowed
            CaptchaService::RecaptchaV2 => Self {
                script: vec![
                    Source::url("https://www.recaptcha.net/recaptcha/"),
                    Source::url("https://www.google.com/recaptcha/"),
                    Source::url("https://www.gstatic.com/recaptcha/"),
                ],
                style: Vec::new(),
                connect: vec![
                    Source::url("https://www.recaptcha.net/recaptcha/"),
                    Source::url("https://www.google.com/recaptcha/"),
                ],
                frame: vec![
                    Source::url("https://www.recaptcha.net/"),
                    Source::url("https://www.google.com/recaptcha/"),
                    Source::url("https://recaptcha.google.com/recaptcha/"),
                ],
            },

            CaptchaService::CloudflareTurnstile => Self {
                script: vec![Source::url(
                    "https://challenges.cloudflare.com/turnstile/v0/",
                )],
                // The SDK styles through CSSOM, which no directive governs
                style: Vec::new(),
                connect: vec![Source::url("https://challenges.cloudflare.com/")],
                frame: vec![Source::url("https://challenges.cloudflare.com/")],
            },

            CaptchaService::HCaptcha => {
                // Their SDK spreads over the apex and several subdomains, and a
                // `*.` source doesn't match the apex, so their documentation
                // asks for the same pair in all four directives
                let origins = vec![
                    Source::url("https://hcaptcha.com/"),
                    Source::url("https://*.hcaptcha.com/"),
                ];

                Self {
                    script: origins.clone(),
                    style: origins.clone(),
                    connect: origins.clone(),
                    frame: origins,
                }
            }
        }
    }
}

/// A policy: which sources each directive allows.
///
/// Ordered, because the serialization has to be stable — the policies are
/// golden tested, and a header which reshuffles itself between builds is a
/// nuisance to diff and to read in a browser's console.
#[derive(Default)]
struct Policy(IndexMap<&'static str, Vec<Source>>);

impl Policy {
    /// Allow some sources for a directive, on top of whatever it already
    /// allows.
    ///
    /// An empty list is a no-op, which is how the optional sources — a
    /// cross-origin assets host, the captcha provider, the plan iframe — fall
    /// out of a policy which doesn't need them. That only works because every
    /// directive which can end up empty here is a fetch directive, covered by
    /// `default-src 'none'`; `form-action`, `frame-ancestors` and `base-uri`
    /// have no such fallback, and leaving one of those out means unrestricted.
    fn allow(mut self, directive: &'static str, sources: impl IntoIterator<Item = Source>) -> Self {
        let mut sources = sources.into_iter().peekable();
        if sources.peek().is_none() {
            return self;
        }

        self.0.entry(directive).or_default().extend(sources);
        self
    }

    /// Every source is either one of the [`Source`] literals, an origin
    /// serialization or a URL scheme, so this can't fail: the URL parser
    /// rejects the bytes a header value would refuse.
    fn finish(self) -> HeaderValue {
        let policy = self
            .0
            .into_iter()
            .map(|(directive, sources)| {
                let sources: Vec<String> = sources.iter().map(Source::to_string).collect();
                format!("{directive} {}", sources.join(" "))
            })
            .collect::<Vec<_>>()
            .join("; ");

        HeaderValue::try_from(policy).expect("policy is a valid header value")
    }
}

/// Where a URI reference from the configuration points, as a policy sees it.
enum Target {
    /// Our own origin, which every policy already covers with `'self'`
    SameOrigin,

    /// Somewhere else
    Other(Source),
}

/// Resolve a URI reference from the configuration the way a browser will:
/// against the public base URL, so a relative reference — which is how a
/// deployment serving the thing itself writes it — lands on our own origin.
///
/// `None` when a source expression can't name where it points, in which case
/// the caller leaves it out and whatever it points at is blocked. That is the
/// safe failure, and it means no configured string is ever copied into a
/// header.
fn config_target(uri: &str, url_builder: &UrlBuilder) -> Option<Target> {
    let base = url_builder.http_base();
    let origin = Url::options()
        .base_url(Some(&base))
        .parse(uri)
        .ok()?
        .origin();

    if origin == base.origin() {
        return Some(Target::SameOrigin);
    }

    Source::origin(&origin).map(Target::Other)
}

/// The `form-action` source for a client redirect URI.
///
/// `None` when a source expression can't name it, in which case the caller
/// leaves the directive out and form submissions stay unrestricted. That is
/// deliberate: `form-action` has no `default-src` fallback, so a source the
/// browser drops would leave it with nothing valid and block the submission
/// outright.
fn form_action_source(redirect_uri: &Url) -> Option<Source> {
    match redirect_uri.scheme() {
        "http" | "https" => Source::origin(&redirect_uri.origin()),
        // Native clients also use custom schemes, which have an opaque origin.
        // `form_post` can't actually deliver the parameters to one — the POST
        // body is dropped when the browser hands the URL to an external
        // protocol handler — but the scheme is the closest we can express.
        scheme => Some(Source::scheme(scheme.to_owned())),
    }
}

/// The policy for the server-rendered pages.
///
/// `form_action` is a parameter because the consent and policy violation pages
/// render a "Cancel" button which, in `form_post` response mode, posts straight
/// to the client's redirect URI.
fn human_policy(assets: &[Source], captcha: &CaptchaSources, form_action: Vec<Source>) -> Policy {
    Policy::default()
        .allow("default-src", [Source::Nothing])
        .allow("script-src", [Source::SameOrigin])
        .allow("script-src", assets.iter().cloned())
        .allow("script-src", captcha.script.iter().cloned())
        .allow("style-src", [Source::SameOrigin])
        .allow("style-src", assets.iter().cloned())
        .allow("style-src", captcha.style.iter().cloned())
        .allow("font-src", [Source::SameOrigin])
        .allow("font-src", assets.iter().cloned())
        .allow("img-src", [Source::SameOrigin])
        .allow("img-src", assets.iter().cloned())
        // for the client `logo_uri`, hot-linked on the consent, device consent
        // and policy violation pages
        .allow("img-src", [Source::scheme("https")])
        .allow("connect-src", [Source::SameOrigin])
        .allow("connect-src", captcha.connect.iter().cloned())
        // `worker-src` falls back through `child-src` to `script-src`, not to
        // `default-src`, so a policy which allows scripts also allows
        // registering a service worker unless this says otherwise
        .allow("worker-src", [Source::Nothing])
        .allow("frame-src", captcha.frame.iter().cloned())
        .allow("form-action", form_action)
        .allow("frame-ancestors", [Source::Nothing])
        .allow("base-uri", [Source::Nothing])
        .allow("object-src", [Source::Nothing])
}

/// The policy for the `form_post` authorization response, which auto-submits a
/// form to the client's redirect URI.
///
/// The server-rendered page policy without the captcha sources, which that page
/// never loads.
fn form_post_policy(assets: &[Source], form_action: Option<Source>) -> Policy {
    Policy::default()
        .allow("default-src", [Source::Nothing])
        .allow("script-src", [Source::SameOrigin])
        .allow("script-src", assets.iter().cloned())
        .allow("style-src", [Source::SameOrigin])
        .allow("style-src", assets.iter().cloned())
        .allow("font-src", [Source::SameOrigin])
        .allow("font-src", assets.iter().cloned())
        .allow("img-src", [Source::SameOrigin])
        .allow("img-src", assets.iter().cloned())
        // for the client `logo_uri`, hot-linked on that page
        .allow("img-src", [Source::scheme("https")])
        .allow("connect-src", [Source::SameOrigin])
        .allow("worker-src", [Source::Nothing])
        // With nothing to name, the directive is left out rather than emitted
        // with a source the browser would drop — see `form_action_source`
        .allow("form-action", form_action)
        .allow("frame-ancestors", [Source::Nothing])
        .allow("base-uri", [Source::Nothing])
        .allow("object-src", [Source::Nothing])
}

/// Nothing is allowed at all: no subresources, no framing, no form target.
///
/// This is the policy any route which forgets to set one of its own inherits,
/// so it names the directives `default-src` doesn't cover.
fn locked_down_policy() -> Policy {
    Policy::default()
        .allow("default-src", [Source::Nothing])
        .allow("form-action", [Source::Nothing])
        .allow("frame-ancestors", [Source::Nothing])
        .allow("base-uri", [Source::Nothing])
}

/// The `Content-Security-Policy` headers served by each kind of route.
#[derive(Clone)]
pub struct Csp {
    /// Server-rendered human-facing pages: login, recovery, consent, device
    /// link, the upstream OAuth pages, the compat SSO redirect, and the error
    /// pages.
    human: HeaderValue,

    /// The password registration page, the only one which loads a captcha.
    register: HeaderValue,

    /// The account SPA shell.
    app: HeaderValue,

    /// The Swagger UI pages.
    swagger: HeaderValue,

    /// Machine endpoints, and the catch-all every other route falls back to.
    locked_down: HeaderValue,

    /// The assets origin, kept around because the policies which name a client
    /// redirect URI are built per response.
    assets: Arc<[Source]>,
}

impl Csp {
    /// Build the policies for a deployment.
    #[must_use]
    pub fn new(site_config: &SiteConfig, url_builder: &UrlBuilder) -> Self {
        let assets_base = url_builder.assets_base();
        let assets: Vec<Source> = match config_target(assets_base, url_builder) {
            Some(Target::SameOrigin) => Vec::new(),
            Some(Target::Other(source)) => vec![source],
            None => {
                tracing::warn!(
                    assets_base,
                    "Assets base URL has no origin which can be named in a Content-Security-Policy; the assets will be blocked"
                );
                Vec::new()
            }
        };

        let captcha = site_config
            .captcha
            .as_ref()
            .map(|captcha| CaptchaSources::for_service(captcha.service))
            .unwrap_or_default();

        // The iframe URI is passed through to the template as-is, so it is
        // resolved here exactly as the browser will resolve it there
        let plan_iframe: Vec<Source> = match site_config.plan_management_iframe_uri.as_deref() {
            None => Vec::new(),
            Some(uri) => match config_target(uri, url_builder) {
                Some(Target::SameOrigin) => vec![Source::SameOrigin],
                Some(Target::Other(source)) => vec![source],
                None => {
                    tracing::warn!(
                        plan_management_iframe_uri = uri,
                        "Plan management iframe URI has no origin which can be named in a Content-Security-Policy; the iframe will be blocked"
                    );
                    Vec::new()
                }
            },
        };

        let app = Policy::default()
            .allow("default-src", [Source::Nothing])
            .allow("script-src", [Source::SameOrigin])
            .allow("script-src", assets.iter().cloned())
            .allow("style-src", [Source::SameOrigin])
            .allow("style-src", assets.iter().cloned())
            // `'unsafe-inline'` is a temporary concession for the `<style>`
            // elements vaul and react-remove-scroll inject at runtime. Keep it
            // here: the server-rendered pages are the auth-critical ones and
            // must not inherit it, so an island on one of those pages must not
            // pull in the drawer.
            .allow("style-src", [Source::UnsafeInline])
            .allow("font-src", [Source::SameOrigin])
            .allow("font-src", assets.iter().cloned())
            .allow("img-src", [Source::SameOrigin])
            .allow("img-src", assets.iter().cloned())
            // `https:` is for the client `logo_uri`; `data:` is for the browser
            // logos, imported inline by `BrowserSession.tsx`
            .allow("img-src", [Source::scheme("https"), Source::scheme("data")])
            // Only the GraphQL endpoint, always a same-origin relative URL.
            // Locales are lazy `import()`s, so they go through `script-src`
            .allow("connect-src", [Source::SameOrigin])
            .allow("worker-src", [Source::Nothing])
            .allow("frame-src", plan_iframe)
            .allow("form-action", [Source::SameOrigin])
            .allow("frame-ancestors", [Source::Nothing])
            .allow("base-uri", [Source::Nothing])
            .allow("object-src", [Source::Nothing])
            .finish();

        // Swagger UI is a large third-party bundle, so it gets its own policy
        // to quarantine anything it needs from the auth-critical pages
        let swagger = Policy::default()
            .allow("default-src", [Source::Nothing])
            .allow("script-src", [Source::SameOrigin])
            .allow("script-src", assets.iter().cloned())
            .allow("style-src", [Source::SameOrigin])
            .allow("style-src", assets.iter().cloned())
            .allow("font-src", [Source::SameOrigin])
            .allow("font-src", assets.iter().cloned())
            .allow("img-src", [Source::SameOrigin])
            .allow("img-src", assets.iter().cloned())
            // `data:` is for the bundle's CSS backgrounds, `blob:` for the
            // response media it renders
            .allow("img-src", [Source::scheme("data"), Source::scheme("blob")])
            .allow("connect-src", [Source::SameOrigin])
            .allow("worker-src", [Source::Nothing])
            .allow("form-action", [Source::SameOrigin])
            .allow("frame-ancestors", [Source::Nothing])
            .allow("base-uri", [Source::Nothing])
            .allow("object-src", [Source::Nothing])
            .finish();

        Self {
            // The captcha provider gets a broad grant — hCaptcha asks for a
            // whole wildcard domain — so it is scoped to the page that needs
            // it rather than handed to every server-rendered page
            human: human_policy(
                &assets,
                &CaptchaSources::default(),
                vec![Source::SameOrigin],
            )
            .finish(),
            register: human_policy(&assets, &captcha, vec![Source::SameOrigin]).finish(),
            app,
            swagger,
            locked_down: locked_down_policy().finish(),
            assets: assets.into(),
        }
    }

    /// Server-rendered human-facing pages.
    #[must_use]
    pub fn human(&self) -> HeaderValue {
        self.human.clone()
    }

    /// A server-rendered page which can post a form straight to the client:
    /// the "Cancel" button on the consent and policy violation pages, when the
    /// grant uses the `form_post` response mode.
    #[must_use]
    pub fn human_posting_to(&self, redirect_uri: &Url) -> HeaderValue {
        // `'self'` is still needed: those pages also post back to us
        let mut form_action = vec![Source::SameOrigin];
        form_action.extend(form_action_source(redirect_uri));

        human_policy(&self.assets, &CaptchaSources::default(), form_action).finish()
    }

    /// The password registration page, which loads the captcha widget.
    #[must_use]
    pub fn register(&self) -> HeaderValue {
        self.register.clone()
    }

    /// The account SPA shell.
    #[must_use]
    pub fn app(&self) -> HeaderValue {
        self.app.clone()
    }

    /// The Swagger UI pages.
    #[must_use]
    pub fn swagger(&self) -> HeaderValue {
        self.swagger.clone()
    }

    /// Machine endpoints, and the catch-all for every other route.
    #[must_use]
    pub fn locked_down(&self) -> HeaderValue {
        self.locked_down.clone()
    }

    /// The `form_post` authorization response, which auto-submits a form to the
    /// client's redirect URI.
    #[must_use]
    pub fn form_post(&self, redirect_uri: &Url) -> HeaderValue {
        form_post_policy(&self.assets, form_action_source(redirect_uri)).finish()
    }
}

impl Default for Csp {
    /// The locked-down policy for every kind of route.
    ///
    /// Only for contexts which have no deployment configuration at hand, such
    /// as the API schema generator.
    fn default() -> Self {
        let locked_down = locked_down_policy().finish();

        Self {
            human: locked_down.clone(),
            register: locked_down.clone(),
            app: locked_down.clone(),
            swagger: locked_down.clone(),
            locked_down,
            assets: Arc::new([]),
        }
    }
}

#[cfg(test)]
mod tests {
    use mas_data_model::{CaptchaConfig, CaptchaService, SiteConfig};
    use mas_router::UrlBuilder;

    use super::Csp;
    use crate::test_utils::test_site_config;

    /// The policies for a deployment with no captcha, no plan iframe and
    /// same-origin assets, which every other test varies one input from.
    const HUMAN: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
                         img-src 'self' https:; connect-src 'self'; worker-src 'none'; form-action 'self'; \
                         frame-ancestors 'none'; base-uri 'none'; object-src 'none'";
    const APP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                       font-src 'self'; img-src 'self' https: data:; connect-src 'self'; worker-src 'none'; \
                       form-action 'self'; frame-ancestors 'none'; base-uri 'none'; \
                       object-src 'none'";
    const SWAGGER: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                           font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; worker-src 'none'; \
                           form-action 'self'; frame-ancestors 'none'; base-uri 'none'; \
                           object-src 'none'";
    const LOCKED_DOWN: &str = "default-src 'none'; form-action 'none'; \
                              frame-ancestors 'none'; base-uri 'none'";

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

        assert_eq!(csp.human(), HUMAN);
        assert_eq!(csp.app(), APP);
        assert_eq!(csp.swagger(), SWAGGER);
        assert_eq!(csp.locked_down(), LOCKED_DOWN);
    }

    /// Without a deployment configuration every route gets the locked-down
    /// policy
    #[test]
    fn test_default() {
        let csp = Csp::default();

        assert_eq!(csp.human(), LOCKED_DOWN);
        assert_eq!(csp.app(), LOCKED_DOWN);
        assert_eq!(csp.swagger(), LOCKED_DOWN);
        assert_eq!(csp.locked_down(), LOCKED_DOWN);
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
             img-src 'self' https://cdn.example.com https:; connect-src 'self'; worker-src 'none'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(
            csp.app(),
            "default-src 'none'; script-src 'self' https://cdn.example.com; \
             style-src 'self' https://cdn.example.com 'unsafe-inline'; \
             font-src 'self' https://cdn.example.com; \
             img-src 'self' https://cdn.example.com https: data:; \
             connect-src 'self'; worker-src 'none'; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(
            csp.swagger(),
            "default-src 'none'; script-src 'self' https://cdn.example.com; \
             style-src 'self' https://cdn.example.com; font-src 'self' https://cdn.example.com; \
             img-src 'self' https://cdn.example.com data: blob:; connect-src 'self'; worker-src 'none'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
        assert_eq!(csp.locked_down(), LOCKED_DOWN);
    }

    /// A non-default port is part of the origin
    #[test]
    fn test_cross_origin_assets_with_port() {
        let csp = Csp::new(
            &site_config(None, None),
            &url_builder(Some("https://cdn.example.com:8443/assets/")),
        );

        assert_eq!(
            csp.human(),
            "default-src 'none'; script-src 'self' https://cdn.example.com:8443; \
             style-src 'self' https://cdn.example.com:8443; \
             font-src 'self' https://cdn.example.com:8443; \
             img-src 'self' https://cdn.example.com:8443 https:; connect-src 'self'; worker-src 'none'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    /// An assets base on our own origin folds into `'self'`, however it is
    /// written
    #[test]
    fn test_same_origin_assets() {
        for assets_base in [
            None,
            Some("/assets/"),
            Some("https://example.com/assets/"),
            Some("//example.com/assets/"),
        ] {
            let csp = Csp::new(&site_config(None, None), &url_builder(assets_base));

            assert_eq!(csp.human(), HUMAN, "assets base {assets_base:?}");
        }
    }

    /// A scheme-relative assets base is cross-origin like any other
    #[test]
    fn test_scheme_relative_cross_origin_assets() {
        let csp = Csp::new(
            &site_config(None, None),
            &url_builder(Some("//cdn.example.com/assets/")),
        );

        assert_eq!(
            csp.human(),
            "default-src 'none'; script-src 'self' https://cdn.example.com; \
             style-src 'self' https://cdn.example.com; font-src 'self' https://cdn.example.com; \
             img-src 'self' https://cdn.example.com https:; connect-src 'self'; worker-src 'none'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    /// An assets origin which can't be named by a source expression is dropped
    /// rather than emitted for a browser to discard
    #[test]
    fn test_unnameable_assets() {
        for assets_base in ["http://[::1]:8080/assets/", "https://cdn_1.example.com/"] {
            let csp = Csp::new(&site_config(None, None), &url_builder(Some(assets_base)));

            assert_eq!(csp.human(), HUMAN, "assets base {assets_base:?}");
        }
    }

    #[test]
    fn test_recaptcha() {
        let csp = Csp::new(
            &site_config(Some(CaptchaService::RecaptchaV2), None),
            &url_builder(None),
        );

        assert_eq!(
            csp.register(),
            "default-src 'none'; \
             script-src 'self' https://www.recaptcha.net/recaptcha/ https://www.google.com/recaptcha/ \
             https://www.gstatic.com/recaptcha/; \
             style-src 'self'; font-src 'self'; img-src 'self' https:; \
             connect-src 'self' https://www.recaptcha.net/recaptcha/ https://www.google.com/recaptcha/; \
             worker-src 'none'; \
             frame-src https://www.recaptcha.net/ https://www.google.com/recaptcha/ \
             https://recaptcha.google.com/recaptcha/; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );

        // No other page loads a captcha, so none of them trusts its origins
        assert_eq!(csp.human(), HUMAN);
        assert_eq!(csp.app(), APP);
        assert_eq!(csp.locked_down(), LOCKED_DOWN);
    }

    #[test]
    fn test_turnstile() {
        let csp = Csp::new(
            &site_config(Some(CaptchaService::CloudflareTurnstile), None),
            &url_builder(None),
        );

        assert_eq!(
            csp.register(),
            "default-src 'none'; \
             script-src 'self' https://challenges.cloudflare.com/turnstile/v0/; \
             style-src 'self'; font-src 'self'; img-src 'self' https:; \
             connect-src 'self' https://challenges.cloudflare.com/; worker-src 'none'; \
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
            csp.register(),
            "default-src 'none'; \
             script-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; \
             style-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; \
             font-src 'self'; img-src 'self' https:; \
             connect-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; worker-src 'none'; \
             frame-src https://hcaptcha.com/ https://*.hcaptcha.com/; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    /// The captcha sources and the assets origin land in the same directives
    #[test]
    fn test_captcha_with_cross_origin_assets() {
        let csp = Csp::new(
            &site_config(Some(CaptchaService::HCaptcha), None),
            &url_builder(Some("https://cdn.example.com/assets/")),
        );

        assert_eq!(
            csp.register(),
            "default-src 'none'; \
             script-src 'self' https://cdn.example.com https://hcaptcha.com/ https://*.hcaptcha.com/; \
             style-src 'self' https://cdn.example.com https://hcaptcha.com/ https://*.hcaptcha.com/; \
             font-src 'self' https://cdn.example.com; \
             img-src 'self' https://cdn.example.com https:; \
             connect-src 'self' https://hcaptcha.com/ https://*.hcaptcha.com/; worker-src 'none'; \
             frame-src https://hcaptcha.com/ https://*.hcaptcha.com/; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    #[test]
    fn test_plan_management_iframe() {
        let csp = Csp::new(
            &site_config(None, Some("https://plan.example.com:8443/embed?foo=bar")),
            &url_builder(None),
        );

        assert_eq!(
            csp.app(),
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             font-src 'self'; img-src 'self' https: data:; connect-src 'self'; worker-src 'none'; \
             frame-src https://plan.example.com:8443; form-action 'self'; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );

        // Only the SPA shell embeds it
        assert_eq!(csp.human(), HUMAN);
    }

    /// The iframe URI is resolved like the browser resolves it, so a relative
    /// one — what a deployment serving the iframe itself uses — is `'self'`
    #[test]
    fn test_relative_plan_management_iframe() {
        for uri in ["/plan", "plan/embed", "https://example.com/plan"] {
            let csp = Csp::new(&site_config(None, Some(uri)), &url_builder(None));

            assert_eq!(
                csp.app(),
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                 font-src 'self'; img-src 'self' https: data:; connect-src 'self'; worker-src 'none'; \
                 frame-src 'self'; form-action 'self'; frame-ancestors 'none'; \
                 base-uri 'none'; object-src 'none'",
                "iframe URI {uri:?}"
            );
        }
    }

    /// An iframe URI with no origin a source expression can name is dropped,
    /// which blocks the iframe rather than emitting something a browser
    /// discards
    #[test]
    fn test_unnameable_plan_management_iframe() {
        for uri in ["data:text/html,hello", "about:blank", "http://[::1]:8080/"] {
            let csp = Csp::new(&site_config(None, Some(uri)), &url_builder(None));

            assert_eq!(csp.app(), APP, "iframe URI {uri:?}");
        }
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
             img-src 'self' https:; connect-src 'self'; worker-src 'none'; form-action https://client.example.com; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );

        // A native client on the loopback interface picks its port at runtime,
        // and the port is part of the origin
        assert_eq!(
            csp.form_post(&"http://127.0.0.1:54321/callback".parse().unwrap()),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; worker-src 'none'; form-action http://127.0.0.1:54321; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );

        // Native clients also use custom schemes, which have an opaque origin
        assert_eq!(
            csp.form_post(&"com.example.app:/callback".parse().unwrap()),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; worker-src 'none'; form-action com.example.app:; \
             frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        );
    }

    /// An IPv6 loopback redirect URI can't be named by a CSP source, so the
    /// directive is left out instead of emitting one browsers would drop —
    /// which would block the submission altogether
    #[test]
    fn test_form_post_ipv6_loopback() {
        let csp = Csp::new(&site_config(None, None), &url_builder(None));

        assert_eq!(
            csp.form_post(&"http://[::1]:54321/callback".parse().unwrap()),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; worker-src 'none'; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'"
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
             img-src 'self' https://cdn.example.com https:; connect-src 'self'; worker-src 'none'; \
             form-action https://client.example.com; frame-ancestors 'none'; base-uri 'none'; \
             object-src 'none'"
        );
    }

    /// The consent and policy violation pages post back to us *and*, through
    /// the "Cancel" button in `form_post` response mode, straight to the client
    #[test]
    fn test_human_posting_to() {
        let csp = Csp::new(&site_config(None, None), &url_builder(None));

        assert_eq!(
            csp.human_posting_to(&"https://client.example.com/callback".parse().unwrap()),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; worker-src 'none'; \
             form-action 'self' https://client.example.com; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'"
        );

        // A redirect URI we can't name leaves `form-action` as it would be
        // without one, rather than dropping the directive: `'self'` still has
        // to be there for the pages' own forms
        assert_eq!(
            csp.human_posting_to(&"http://[::1]:54321/callback".parse().unwrap()),
            csp.human()
        );
    }

    /// The registration page is the only one which trusts the captcha origins
    #[test]
    fn test_register_is_the_only_page_with_captcha() {
        let csp = Csp::new(
            &site_config(Some(CaptchaService::HCaptcha), None),
            &url_builder(None),
        );

        assert_eq!(csp.human(), HUMAN);
        assert_ne!(csp.register(), csp.human());
        assert_eq!(
            csp.human_posting_to(&"https://client.example.com/cb".parse().unwrap()),
            "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
             img-src 'self' https:; connect-src 'self'; worker-src 'none'; \
             form-action 'self' https://client.example.com; frame-ancestors 'none'; \
             base-uri 'none'; object-src 'none'"
        );
    }
}
