// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Contexts used in templates

mod branding;
mod captcha;
mod ext;
mod features;

use std::{
    collections::BTreeMap,
    fmt::Formatter,
    net::{IpAddr, Ipv4Addr},
};

use chrono::{DateTime, Duration, Utc};
use http::{Method, Uri, Version};
use mas_data_model::{
    AuthorizationGrant, BrowserSession, Client, CompatSsoLogin, CompatSsoLoginState,
    DeviceCodeGrant, MatrixUser, UpstreamOAuthLink, UpstreamOAuthProvider,
    UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
    UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderPkceMode,
    UpstreamOAuthProviderTokenAuthMethod, User, UserEmailAuthentication,
    UserEmailAuthenticationCode, UserRecoverySession, UserRegistration,
};
use mas_i18n::DataLocale;
use mas_iana::jose::JsonWebSignatureAlg;
use mas_policy::{Violation, ViolationCode};
use mas_router::{Account, GraphQL, PostAuthAction, UrlBuilder};
use oauth2_types::scope::{OPENID, Scope};
use rand::{
    Rng, SeedableRng,
    distributions::{Alphanumeric, DistString},
};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize, ser::SerializeStruct};
use ulid::Ulid;
use url::Url;

pub use self::{
    branding::SiteBranding, captcha::WithCaptcha, ext::SiteConfigExt, features::SiteFeatures,
};
use crate::{FieldError, FormField, FormState};

/// Helper trait to construct context wrappers
pub trait TemplateContext: Serialize {
    /// Attach a user session to the template context
    fn with_session(self, current_session: BrowserSession) -> WithSession<Self>
    where
        Self: Sized,
    {
        WithSession {
            current_session,
            inner: self,
        }
    }

    /// Attach an optional user session to the template context
    fn maybe_with_session(
        self,
        current_session: Option<BrowserSession>,
    ) -> WithOptionalSession<Self>
    where
        Self: Sized,
    {
        WithOptionalSession {
            current_session,
            inner: self,
        }
    }

    /// Attach a CSRF token to the template context
    fn with_csrf<C>(self, csrf_token: C) -> WithCsrf<Self>
    where
        Self: Sized,
        C: ToString,
    {
        // TODO: make this method use a CsrfToken again
        WithCsrf {
            csrf_token: csrf_token.to_string(),
            inner: self,
        }
    }

    /// Attach a language to the template context
    fn with_language(self, lang: DataLocale) -> WithLanguage<Self>
    where
        Self: Sized,
    {
        WithLanguage {
            lang: lang.to_string(),
            inner: self,
        }
    }

    /// Attach a CAPTCHA configuration to the template context
    fn with_captcha(self, captcha: Option<mas_data_model::CaptchaConfig>) -> WithCaptcha<Self>
    where
        Self: Sized,
    {
        WithCaptcha::new(captcha, self)
    }

    /// Generate sample values for this context type
    ///
    /// This is then used to check for template validity in unit tests and in
    /// the CLI (`cargo run -- templates check`)
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SampleIdentifier {
    pub components: Vec<(&'static str, String)>,
}

impl SampleIdentifier {
    pub fn from_index(index: usize) -> Self {
        Self {
            components: Vec::default(),
        }
        .with_appended("index", format!("{index}"))
    }

    pub fn with_appended(&self, kind: &'static str, locale: String) -> Self {
        let mut new = self.clone();
        new.components.push((kind, locale));
        new
    }
}

pub(crate) fn sample_list<T: TemplateContext>(samples: Vec<T>) -> BTreeMap<SampleIdentifier, T> {
    samples
        .into_iter()
        .enumerate()
        .map(|(index, sample)| (SampleIdentifier::from_index(index), sample))
        .collect()
}

impl TemplateContext for () {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        BTreeMap::new()
    }
}

/// Context with a specified locale in it
#[derive(Serialize, Debug)]
pub struct WithLanguage<T> {
    lang: String,

    #[serde(flatten)]
    inner: T,
}

impl<T> WithLanguage<T> {
    /// Get the language of this context
    pub fn language(&self) -> &str {
        &self.lang
    }
}

impl<T> std::ops::Deref for WithLanguage<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: TemplateContext> TemplateContext for WithLanguage<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        // Create a forked RNG so we make samples deterministic between locales
        let rng = ChaCha8Rng::from_rng(rng).unwrap();
        locales
            .iter()
            .flat_map(|locale| {
                T::sample(now, &mut rng.clone(), locales)
                    .into_iter()
                    .map(|(sample_id, sample)| {
                        (
                            sample_id.with_appended("locale", locale.to_string()),
                            WithLanguage {
                                lang: locale.to_string(),
                                inner: sample,
                            },
                        )
                    })
            })
            .collect()
    }
}

/// Context with a CSRF token in it
#[derive(Serialize, Debug)]
pub struct WithCsrf<T> {
    csrf_token: String,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithCsrf<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        T::sample(now, rng, locales)
            .into_iter()
            .map(|(k, inner)| {
                (
                    k,
                    WithCsrf {
                        csrf_token: "fake_csrf_token".into(),
                        inner,
                    },
                )
            })
            .collect()
    }
}

/// Context with a user session in it
#[derive(Serialize)]
pub struct WithSession<T> {
    current_session: BrowserSession,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithSession<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        BrowserSession::samples(now, rng)
            .into_iter()
            .enumerate()
            .flat_map(|(session_index, session)| {
                T::sample(now, rng, locales)
                    .into_iter()
                    .map(move |(k, inner)| {
                        (
                            k.with_appended("browser-session", session_index.to_string()),
                            WithSession {
                                current_session: session.clone(),
                                inner,
                            },
                        )
                    })
            })
            .collect()
    }
}

/// Context with an optional user session in it
#[derive(Serialize)]
pub struct WithOptionalSession<T> {
    current_session: Option<BrowserSession>,

    #[serde(flatten)]
    inner: T,
}

impl<T: TemplateContext> TemplateContext for WithOptionalSession<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        BrowserSession::samples(now, rng)
            .into_iter()
            .map(Some) // Wrap all samples in an Option
            .chain(std::iter::once(None)) // Add the "None" option
            .enumerate()
            .flat_map(|(session_index, session)| {
                T::sample(now, rng, locales)
                    .into_iter()
                    .map(move |(k, inner)| {
                        (
                            if session.is_some() {
                                k.with_appended("browser-session", session_index.to_string())
                            } else {
                                k
                            },
                            WithOptionalSession {
                                current_session: session.clone(),
                                inner,
                            },
                        )
                    })
            })
            .collect()
    }
}

/// An empty context used for composition
pub struct EmptyContext;

impl Serialize for EmptyContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("EmptyContext", 0)?;
        // FIXME: for some reason, serde seems to not like struct flattening with empty
        // stuff
        s.serialize_field("__UNUSED", &())?;
        s.end()
    }
}

impl TemplateContext for EmptyContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![EmptyContext])
    }
}

/// Context used by the `index.html` template
#[derive(Serialize)]
pub struct IndexContext {
    discovery_url: Url,
}

impl IndexContext {
    /// Constructs the context for the index page from the OIDC discovery
    /// document URL
    #[must_use]
    pub fn new(discovery_url: Url) -> Self {
        Self { discovery_url }
    }
}

impl TemplateContext for IndexContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![Self {
            discovery_url: "https://example.com/.well-known/openid-configuration"
                .parse()
                .unwrap(),
        }])
    }
}

/// Config used by the frontend app
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfig {
    root: String,
    graphql_endpoint: String,
}

/// Context used by the `app.html` template
#[derive(Serialize)]
pub struct AppContext {
    app_config: AppConfig,
}

impl AppContext {
    /// Constructs the context given the [`UrlBuilder`]
    #[must_use]
    pub fn from_url_builder(url_builder: &UrlBuilder) -> Self {
        let root = url_builder.relative_url_for(&Account::default());
        let graphql_endpoint = url_builder.relative_url_for(&GraphQL);
        Self {
            app_config: AppConfig {
                root,
                graphql_endpoint,
            },
        }
    }
}

impl TemplateContext for AppContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        sample_list(vec![Self::from_url_builder(&url_builder)])
    }
}

/// Context used by the `swagger/doc.html` template
#[derive(Serialize)]
pub struct ApiDocContext {
    openapi_url: Url,
    callback_url: Url,
}

impl ApiDocContext {
    /// Constructs a context for the API documentation page giben the
    /// [`UrlBuilder`]
    #[must_use]
    pub fn from_url_builder(url_builder: &UrlBuilder) -> Self {
        Self {
            openapi_url: url_builder.absolute_url_for(&mas_router::ApiSpec),
            callback_url: url_builder.absolute_url_for(&mas_router::ApiDocCallback),
        }
    }
}

impl TemplateContext for ApiDocContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let url_builder = UrlBuilder::new("https://example.com/".parse().unwrap(), None, None);
        sample_list(vec![Self::from_url_builder(&url_builder)])
    }
}

/// Fields of the login form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoginFormField {
    /// The username field
    Username,

    /// The password field
    Password,

    /// The passkey challenge
    PasskeyChallengeId,

    /// The passkey response
    PasskeyResponse,
}

impl FormField for LoginFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Username | Self::PasskeyChallengeId => true,
            Self::Password | Self::PasskeyResponse => false,
        }
    }
}

/// Inner context used in login screen. See [`PostAuthContext`].
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PostAuthContextInner {
    /// Continue an authorization grant
    ContinueAuthorizationGrant {
        /// The authorization grant that will be continued after authentication
        grant: Box<AuthorizationGrant>,
    },

    /// Continue a device code grant
    ContinueDeviceCodeGrant {
        /// The device code grant that will be continued after authentication
        grant: Box<DeviceCodeGrant>,
    },

    /// Continue legacy login
    /// TODO: add the login context in there
    ContinueCompatSsoLogin {
        /// The compat SSO login request
        login: Box<CompatSsoLogin>,
    },

    /// Change the account password
    ChangePassword,

    /// Link an upstream account
    LinkUpstream {
        /// The upstream provider
        provider: Box<UpstreamOAuthProvider>,

        /// The link
        link: Box<UpstreamOAuthLink>,
    },

    /// Go to the account management page
    ManageAccount,
}

/// Context used in login screen, for the post-auth action to do
#[derive(Serialize)]
pub struct PostAuthContext {
    /// The post auth action params from the URL
    pub params: PostAuthAction,

    /// The loaded post auth context
    #[serde(flatten)]
    pub ctx: PostAuthContextInner,
}

/// Context used by the `login.html` template
#[derive(Serialize, Default)]
pub struct LoginContext {
    form: FormState<LoginFormField>,
    next: Option<PostAuthContext>,
    providers: Vec<UpstreamOAuthProvider>,
    webauthn_options: String,
}

impl TemplateContext for LoginContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        sample_list(vec![
            LoginContext {
                form: FormState::default(),
                next: None,
                providers: Vec::new(),
                webauthn_options: String::new(),
            },
            LoginContext {
                form: FormState::default(),
                next: None,
                providers: Vec::new(),
                webauthn_options: String::new(),
            },
            LoginContext {
                form: FormState::default()
                    .with_error_on_field(LoginFormField::Username, FieldError::Required)
                    .with_error_on_field(
                        LoginFormField::Password,
                        FieldError::Policy {
                            code: None,
                            message: "password too short".to_owned(),
                        },
                    ),
                next: None,
                providers: Vec::new(),
                webauthn_options: String::new(),
            },
            LoginContext {
                form: FormState::default()
                    .with_error_on_field(LoginFormField::Username, FieldError::Exists),
                next: None,
                providers: Vec::new(),
                webauthn_options: String::new(),
            },
        ])
    }
}

impl LoginContext {
    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form: FormState<LoginFormField>) -> Self {
        Self { form, ..self }
    }

    /// Mutably borrow the form state
    pub fn form_state_mut(&mut self) -> &mut FormState<LoginFormField> {
        &mut self.form
    }

    /// Set the upstream OAuth 2.0 providers
    #[must_use]
    pub fn with_upstream_providers(self, providers: Vec<UpstreamOAuthProvider>) -> Self {
        Self { providers, ..self }
    }

    /// Add a post authentication action to the context
    #[must_use]
    pub fn with_post_action(self, context: PostAuthContext) -> Self {
        Self {
            next: Some(context),
            ..self
        }
    }

    /// Set the webauthn options
    #[must_use]
    pub fn with_webauthn_options(self, webauthn_options: String) -> Self {
        Self {
            webauthn_options,
            ..self
        }
    }
}

/// Fields of the registration form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterFormField {
    /// The username field
    Username,

    /// The email field
    Email,

    /// The password field
    Password,

    /// The password confirmation field
    PasswordConfirm,

    /// The terms of service agreement field
    AcceptTerms,
}

impl FormField for RegisterFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Username | Self::Email | Self::AcceptTerms => true,
            Self::Password | Self::PasswordConfirm => false,
        }
    }
}

/// Context used by the `register.html` template
#[derive(Serialize, Default)]
pub struct RegisterContext {
    providers: Vec<UpstreamOAuthProvider>,
    next: Option<PostAuthContext>,
}

impl TemplateContext for RegisterContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![RegisterContext {
            providers: Vec::new(),
            next: None,
        }])
    }
}

impl RegisterContext {
    /// Create a new context with the given upstream providers
    #[must_use]
    pub fn new(providers: Vec<UpstreamOAuthProvider>) -> Self {
        Self {
            providers,
            next: None,
        }
    }

    /// Add a post authentication action to the context
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

/// Context used by the `password_register.html` template
#[derive(Serialize, Default)]
pub struct PasswordRegisterContext {
    form: FormState<RegisterFormField>,
    next: Option<PostAuthContext>,
}

impl TemplateContext for PasswordRegisterContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        // TODO: samples with errors
        sample_list(vec![PasswordRegisterContext {
            form: FormState::default(),
            next: None,
        }])
    }
}

impl PasswordRegisterContext {
    /// Add an error on the registration form
    #[must_use]
    pub fn with_form_state(self, form: FormState<RegisterFormField>) -> Self {
        Self { form, ..self }
    }

    /// Add a post authentication action to the context
    #[must_use]
    pub fn with_post_action(self, next: PostAuthContext) -> Self {
        Self {
            next: Some(next),
            ..self
        }
    }
}

/// Context used by the `consent.html` template
#[derive(Serialize)]
pub struct ConsentContext {
    grant: AuthorizationGrant,
    client: Client,
    action: PostAuthAction,
    matrix_user: MatrixUser,
}

impl TemplateContext for ConsentContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            Client::samples(now, rng)
                .into_iter()
                .map(|client| {
                    let mut grant = AuthorizationGrant::sample(now, rng);
                    let action = PostAuthAction::continue_grant(grant.id);
                    // XXX
                    grant.client_id = client.id;
                    Self {
                        grant,
                        client,
                        action,
                        matrix_user: MatrixUser {
                            mxid: "@alice:example.com".to_owned(),
                            display_name: Some("Alice".to_owned()),
                        },
                    }
                })
                .collect(),
        )
    }
}

impl ConsentContext {
    /// Constructs a context for the client consent page
    #[must_use]
    pub fn new(grant: AuthorizationGrant, client: Client, matrix_user: MatrixUser) -> Self {
        let action = PostAuthAction::continue_grant(grant.id);
        Self {
            grant,
            client,
            action,
            matrix_user,
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "grant_type")]
enum PolicyViolationGrant {
    #[serde(rename = "authorization_code")]
    Authorization(AuthorizationGrant),
    #[serde(rename = "urn:ietf:params:oauth:grant-type:device_code")]
    DeviceCode(DeviceCodeGrant),
}

/// Context used by the `policy_violation.html` template
#[derive(Serialize)]
pub struct PolicyViolationContext {
    grant: PolicyViolationGrant,
    client: Client,
    action: PostAuthAction,
}

impl TemplateContext for PolicyViolationContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            Client::samples(now, rng)
                .into_iter()
                .flat_map(|client| {
                    let mut grant = AuthorizationGrant::sample(now, rng);
                    // XXX
                    grant.client_id = client.id;

                    let authorization_grant =
                        PolicyViolationContext::for_authorization_grant(grant, client.clone());
                    let device_code_grant = PolicyViolationContext::for_device_code_grant(
                        DeviceCodeGrant {
                            id: Ulid::from_datetime_with_source(now.into(), rng),
                            state: mas_data_model::DeviceCodeGrantState::Pending,
                            client_id: client.id,
                            scope: [OPENID].into_iter().collect(),
                            user_code: Alphanumeric.sample_string(rng, 6).to_uppercase(),
                            device_code: Alphanumeric.sample_string(rng, 32),
                            created_at: now - Duration::try_minutes(5).unwrap(),
                            expires_at: now + Duration::try_minutes(25).unwrap(),
                            ip_address: None,
                            user_agent: None,
                        },
                        client,
                    );

                    [authorization_grant, device_code_grant]
                })
                .collect(),
        )
    }
}

impl PolicyViolationContext {
    /// Constructs a context for the policy violation page for an authorization
    /// grant
    #[must_use]
    pub const fn for_authorization_grant(grant: AuthorizationGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_grant(grant.id);
        Self {
            grant: PolicyViolationGrant::Authorization(grant),
            client,
            action,
        }
    }

    /// Constructs a context for the policy violation page for a device code
    /// grant
    #[must_use]
    pub const fn for_device_code_grant(grant: DeviceCodeGrant, client: Client) -> Self {
        let action = PostAuthAction::continue_device_code_grant(grant.id);
        Self {
            grant: PolicyViolationGrant::DeviceCode(grant),
            client,
            action,
        }
    }
}

/// Context used by the `compat_login_policy_violation.html` template
#[derive(Serialize)]
pub struct CompatLoginPolicyViolationContext {
    violations: Vec<Violation>,
}

impl TemplateContext for CompatLoginPolicyViolationContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            CompatLoginPolicyViolationContext { violations: vec![] },
            CompatLoginPolicyViolationContext {
                violations: vec![Violation {
                    msg: "user has too many active sessions".to_owned(),
                    redirect_uri: None,
                    field: None,
                    code: Some(ViolationCode::TooManySessions),
                }],
            },
        ])
    }
}

impl CompatLoginPolicyViolationContext {
    /// Constructs a context for the compatibility login policy violation page
    /// given the list of violations
    #[must_use]
    pub const fn for_violations(violations: Vec<Violation>) -> Self {
        Self { violations }
    }
}

/// Context used by the `sso.html` template
#[derive(Serialize)]
pub struct CompatSsoContext {
    login: CompatSsoLogin,
    action: PostAuthAction,
    matrix_user: MatrixUser,
}

impl TemplateContext for CompatSsoContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        sample_list(vec![CompatSsoContext::new(
            CompatSsoLogin {
                id,
                redirect_uri: Url::parse("https://app.element.io/").unwrap(),
                login_token: "abcdefghijklmnopqrstuvwxyz012345".into(),
                created_at: now,
                state: CompatSsoLoginState::Pending,
            },
            MatrixUser {
                mxid: "@alice:example.com".to_owned(),
                display_name: Some("Alice".to_owned()),
            },
        )])
    }
}

impl CompatSsoContext {
    /// Constructs a context for the legacy SSO login page
    #[must_use]
    pub fn new(login: CompatSsoLogin, matrix_user: MatrixUser) -> Self
where {
        let action = PostAuthAction::continue_compat_sso_login(login.id);
        Self {
            login,
            action,
            matrix_user,
        }
    }
}

/// Context used by the `emails/recovery.{txt,html,subject}` templates
#[derive(Serialize)]
pub struct EmailRecoveryContext {
    user: User,
    session: UserRecoverySession,
    recovery_link: Url,
}

impl EmailRecoveryContext {
    /// Constructs a context for the recovery email
    #[must_use]
    pub fn new(user: User, session: UserRecoverySession, recovery_link: Url) -> Self {
        Self {
            user,
            session,
            recovery_link,
        }
    }

    /// Returns the user associated with the recovery email
    #[must_use]
    pub fn user(&self) -> &User {
        &self.user
    }

    /// Returns the recovery session associated with the recovery email
    #[must_use]
    pub fn session(&self) -> &UserRecoverySession {
        &self.session
    }
}

impl TemplateContext for EmailRecoveryContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(User::samples(now, rng).into_iter().map(|user| {
            let session = UserRecoverySession {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                email: "hello@example.com".to_owned(),
                user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/536.30.1 (KHTML, like Gecko) Version/6.0.5 Safari/536.30.1".to_owned(),
                ip_address: Some(IpAddr::from([192_u8, 0, 2, 1])),
                locale: "en".to_owned(),
                created_at: now,
                consumed_at: None,
            };

            let link = "https://example.com/recovery/complete?ticket=abcdefghijklmnopqrstuvwxyz0123456789".parse().unwrap();

            Self::new(user, session, link)
        }).collect())
    }
}

/// Context used by the `emails/verification.{txt,html,subject}` templates
#[derive(Serialize)]
pub struct EmailVerificationContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    browser_session: Option<BrowserSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_registration: Option<UserRegistration>,
    authentication_code: UserEmailAuthenticationCode,
}

impl EmailVerificationContext {
    /// Constructs a context for the verification email
    #[must_use]
    pub fn new(
        authentication_code: UserEmailAuthenticationCode,
        browser_session: Option<BrowserSession>,
        user_registration: Option<UserRegistration>,
    ) -> Self {
        Self {
            browser_session,
            user_registration,
            authentication_code,
        }
    }

    /// Get the user to which this email is being sent
    #[must_use]
    pub fn user(&self) -> Option<&User> {
        self.browser_session.as_ref().map(|s| &s.user)
    }

    /// Get the verification code being sent
    #[must_use]
    pub fn code(&self) -> &str {
        &self.authentication_code.code
    }
}

impl TemplateContext for EmailVerificationContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            BrowserSession::samples(now, rng)
                .into_iter()
                .map(|browser_session| {
                    let authentication_code = UserEmailAuthenticationCode {
                        id: Ulid::from_datetime_with_source(now.into(), rng),
                        user_email_authentication_id: Ulid::from_datetime_with_source(
                            now.into(),
                            rng,
                        ),
                        code: "123456".to_owned(),
                        created_at: now - Duration::try_minutes(5).unwrap(),
                        expires_at: now + Duration::try_minutes(25).unwrap(),
                    };

                    Self {
                        browser_session: Some(browser_session),
                        user_registration: None,
                        authentication_code,
                    }
                })
                .collect(),
        )
    }
}

/// Fields of the email verification form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsVerifyEmailFormField {
    /// The code field
    Code,
}

impl FormField for RegisterStepsVerifyEmailFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Code => true,
        }
    }
}

/// Context used by the `pages/register/steps/verify_email.html` templates
#[derive(Serialize)]
pub struct RegisterStepsVerifyEmailContext {
    form: FormState<RegisterStepsVerifyEmailFormField>,
    authentication: UserEmailAuthentication,
}

impl RegisterStepsVerifyEmailContext {
    /// Constructs a context for the email verification page
    #[must_use]
    pub fn new(authentication: UserEmailAuthentication) -> Self {
        Self {
            form: FormState::default(),
            authentication,
        }
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form: FormState<RegisterStepsVerifyEmailFormField>) -> Self {
        Self { form, ..self }
    }
}

impl TemplateContext for RegisterStepsVerifyEmailContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let authentication = UserEmailAuthentication {
            id: Ulid::from_datetime_with_source(now.into(), rng),
            user_session_id: None,
            user_registration_id: None,
            email: "foobar@example.com".to_owned(),
            created_at: now,
            completed_at: None,
        };

        sample_list(vec![Self {
            form: FormState::default(),
            authentication,
        }])
    }
}

/// Context used by the `pages/register/steps/email_in_use.html` template
#[derive(Serialize)]
pub struct RegisterStepsEmailInUseContext {
    email: String,
    action: Option<PostAuthAction>,
}

impl RegisterStepsEmailInUseContext {
    /// Constructs a context for the email in use page
    #[must_use]
    pub fn new(email: String, action: Option<PostAuthAction>) -> Self {
        Self { email, action }
    }
}

impl TemplateContext for RegisterStepsEmailInUseContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let email = "hello@example.com".to_owned();
        let action = PostAuthAction::continue_grant(Ulid::nil());
        sample_list(vec![Self::new(email, Some(action))])
    }
}

/// Fields for the display name form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsDisplayNameFormField {
    /// The display name
    DisplayName,
}

impl FormField for RegisterStepsDisplayNameFormField {
    fn keep(&self) -> bool {
        match self {
            Self::DisplayName => true,
        }
    }
}

/// Context used by the `display_name.html` template
#[derive(Serialize, Default)]
pub struct RegisterStepsDisplayNameContext {
    form: FormState<RegisterStepsDisplayNameFormField>,
}

impl RegisterStepsDisplayNameContext {
    /// Constructs a context for the display name page
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(
        mut self,
        form_state: FormState<RegisterStepsDisplayNameFormField>,
    ) -> Self {
        self.form = form_state;
        self
    }
}

impl TemplateContext for RegisterStepsDisplayNameContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![Self {
            form: FormState::default(),
        }])
    }
}

/// Fields of the registration token form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegisterStepsRegistrationTokenFormField {
    /// The registration token
    Token,
}

impl FormField for RegisterStepsRegistrationTokenFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Token => true,
        }
    }
}

/// The registration token page context
#[derive(Serialize, Default)]
pub struct RegisterStepsRegistrationTokenContext {
    form: FormState<RegisterStepsRegistrationTokenFormField>,
}

impl RegisterStepsRegistrationTokenContext {
    /// Constructs a context for the registration token page
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(
        mut self,
        form_state: FormState<RegisterStepsRegistrationTokenFormField>,
    ) -> Self {
        self.form = form_state;
        self
    }
}

impl TemplateContext for RegisterStepsRegistrationTokenContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<chrono::Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![Self {
            form: FormState::default(),
        }])
    }
}

/// Fields of the account recovery start form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStartFormField {
    /// The email
    Email,
}

impl FormField for RecoveryStartFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Email => true,
        }
    }
}

/// Context used by the `pages/recovery/start.html` template
#[derive(Serialize, Default)]
pub struct RecoveryStartContext {
    form: FormState<RecoveryStartFormField>,
}

impl RecoveryStartContext {
    /// Constructs a context for the recovery start page
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form: FormState<RecoveryStartFormField>) -> Self {
        Self { form }
    }
}

impl TemplateContext for RecoveryStartContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            Self::new(),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(RecoveryStartFormField::Email, FieldError::Required),
            ),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(RecoveryStartFormField::Email, FieldError::Invalid),
            ),
        ])
    }
}

/// Context used by the `pages/recovery/progress.html` template
#[derive(Serialize)]
pub struct RecoveryProgressContext {
    session: UserRecoverySession,
    /// Whether resending the e-mail was denied because of rate limits
    resend_failed_due_to_rate_limit: bool,
}

impl RecoveryProgressContext {
    /// Constructs a context for the recovery progress page
    #[must_use]
    pub fn new(session: UserRecoverySession, resend_failed_due_to_rate_limit: bool) -> Self {
        Self {
            session,
            resend_failed_due_to_rate_limit,
        }
    }
}

impl TemplateContext for RecoveryProgressContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let session = UserRecoverySession {
            id: Ulid::from_datetime_with_source(now.into(), rng),
            email: "name@mail.com".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            ip_address: None,
            locale: "en".to_owned(),
            created_at: now,
            consumed_at: None,
        };

        sample_list(vec![
            Self {
                session: session.clone(),
                resend_failed_due_to_rate_limit: false,
            },
            Self {
                session,
                resend_failed_due_to_rate_limit: true,
            },
        ])
    }
}

/// Context used by the `pages/recovery/expired.html` template
#[derive(Serialize)]
pub struct RecoveryExpiredContext {
    session: UserRecoverySession,
}

impl RecoveryExpiredContext {
    /// Constructs a context for the recovery expired page
    #[must_use]
    pub fn new(session: UserRecoverySession) -> Self {
        Self { session }
    }
}

impl TemplateContext for RecoveryExpiredContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let session = UserRecoverySession {
            id: Ulid::from_datetime_with_source(now.into(), rng),
            email: "name@mail.com".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            ip_address: None,
            locale: "en".to_owned(),
            created_at: now,
            consumed_at: None,
        };

        sample_list(vec![Self { session }])
    }
}
/// Fields of the account recovery finish form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFinishFormField {
    /// The new password
    NewPassword,

    /// The new password confirmation
    NewPasswordConfirm,
}

impl FormField for RecoveryFinishFormField {
    fn keep(&self) -> bool {
        false
    }
}

/// Context used by the `pages/recovery/finish.html` template
#[derive(Serialize)]
pub struct RecoveryFinishContext {
    user: User,
    form: FormState<RecoveryFinishFormField>,
}

impl RecoveryFinishContext {
    /// Constructs a context for the recovery finish page
    #[must_use]
    pub fn new(user: User) -> Self {
        Self {
            user,
            form: FormState::default(),
        }
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(mut self, form: FormState<RecoveryFinishFormField>) -> Self {
        self.form = form;
        self
    }
}

impl TemplateContext for RecoveryFinishContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .flat_map(|user| {
                    vec![
                        Self::new(user.clone()),
                        Self::new(user.clone()).with_form_state(
                            FormState::default().with_error_on_field(
                                RecoveryFinishFormField::NewPassword,
                                FieldError::Invalid,
                            ),
                        ),
                        Self::new(user.clone()).with_form_state(
                            FormState::default().with_error_on_field(
                                RecoveryFinishFormField::NewPasswordConfirm,
                                FieldError::Invalid,
                            ),
                        ),
                    ]
                })
                .collect(),
        )
    }
}

/// Context used by the `pages/upstream_oauth2/link_mismatch.html`
/// templates
#[derive(Serialize)]
pub struct UpstreamExistingLinkContext {
    linked_user: User,
}

impl UpstreamExistingLinkContext {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new(linked_user: User) -> Self {
        Self { linked_user }
    }
}

impl TemplateContext for UpstreamExistingLinkContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .map(|linked_user| Self { linked_user })
                .collect(),
        )
    }
}

/// Context used by the `pages/upstream_oauth2/suggest_link.html`
/// templates
#[derive(Serialize)]
pub struct UpstreamSuggestLink {
    post_logout_action: PostAuthAction,
}

impl UpstreamSuggestLink {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new(link: &UpstreamOAuthLink) -> Self {
        Self::for_link_id(link.id)
    }

    fn for_link_id(id: Ulid) -> Self {
        let post_logout_action = PostAuthAction::link_upstream(id);
        Self { post_logout_action }
    }
}

impl TemplateContext for UpstreamSuggestLink {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let id = Ulid::from_datetime_with_source(now.into(), rng);
        sample_list(vec![Self::for_link_id(id)])
    }
}

/// User-editeable fields of the upstream account link form
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamRegisterFormField {
    /// The username field
    Username,

    /// Accept the terms of service
    AcceptTerms,
}

impl FormField for UpstreamRegisterFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Username | Self::AcceptTerms => true,
        }
    }
}

/// Context used by the `pages/upstream_oauth2/do_register.html`
/// templates
#[derive(Serialize)]
pub struct UpstreamRegister {
    upstream_oauth_link: UpstreamOAuthLink,
    upstream_oauth_provider: UpstreamOAuthProvider,
    imported_localpart: Option<String>,
    force_localpart: bool,
    imported_display_name: Option<String>,
    force_display_name: bool,
    imported_email: Option<String>,
    force_email: bool,
    form_state: FormState<UpstreamRegisterFormField>,
}

impl UpstreamRegister {
    /// Constructs a new context for registering a new user from an upstream
    /// provider
    #[must_use]
    pub fn new(
        upstream_oauth_link: UpstreamOAuthLink,
        upstream_oauth_provider: UpstreamOAuthProvider,
    ) -> Self {
        Self {
            upstream_oauth_link,
            upstream_oauth_provider,
            imported_localpart: None,
            force_localpart: false,
            imported_display_name: None,
            force_display_name: false,
            imported_email: None,
            force_email: false,
            form_state: FormState::default(),
        }
    }

    /// Set the imported localpart
    pub fn set_localpart(&mut self, localpart: String, force: bool) {
        self.imported_localpart = Some(localpart);
        self.force_localpart = force;
    }

    /// Set the imported localpart
    #[must_use]
    pub fn with_localpart(self, localpart: String, force: bool) -> Self {
        Self {
            imported_localpart: Some(localpart),
            force_localpart: force,
            ..self
        }
    }

    /// Set the imported display name
    pub fn set_display_name(&mut self, display_name: String, force: bool) {
        self.imported_display_name = Some(display_name);
        self.force_display_name = force;
    }

    /// Set the imported display name
    #[must_use]
    pub fn with_display_name(self, display_name: String, force: bool) -> Self {
        Self {
            imported_display_name: Some(display_name),
            force_display_name: force,
            ..self
        }
    }

    /// Set the imported email
    pub fn set_email(&mut self, email: String, force: bool) {
        self.imported_email = Some(email);
        self.force_email = force;
    }

    /// Set the imported email
    #[must_use]
    pub fn with_email(self, email: String, force: bool) -> Self {
        Self {
            imported_email: Some(email),
            force_email: force,
            ..self
        }
    }

    /// Set the form state
    pub fn set_form_state(&mut self, form_state: FormState<UpstreamRegisterFormField>) {
        self.form_state = form_state;
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(self, form_state: FormState<UpstreamRegisterFormField>) -> Self {
        Self { form_state, ..self }
    }
}

impl TemplateContext for UpstreamRegister {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![Self::new(
            UpstreamOAuthLink {
                id: Ulid::nil(),
                provider_id: Ulid::nil(),
                user_id: None,
                subject: "subject".to_owned(),
                human_account_name: Some("@john".to_owned()),
                created_at: now,
            },
            UpstreamOAuthProvider {
                id: Ulid::nil(),
                issuer: Some("https://example.com/".to_owned()),
                human_name: Some("Example Ltd.".to_owned()),
                brand_name: None,
                scope: Scope::from_iter([OPENID]),
                token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
                token_endpoint_signing_alg: None,
                id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                client_id: "client-id".to_owned(),
                encrypted_client_secret: None,
                claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                authorization_endpoint_override: None,
                token_endpoint_override: None,
                jwks_uri_override: None,
                userinfo_endpoint_override: None,
                fetch_userinfo: false,
                userinfo_signed_response_alg: None,
                discovery_mode: UpstreamOAuthProviderDiscoveryMode::Oidc,
                pkce_mode: UpstreamOAuthProviderPkceMode::Auto,
                response_mode: None,
                additional_authorization_parameters: Vec::new(),
                forward_login_hint: false,
                created_at: now,
                disabled_at: None,
                on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            },
        )])
    }
}

/// Form fields on the device link page
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLinkFormField {
    /// The device code field
    Code,
}

impl FormField for DeviceLinkFormField {
    fn keep(&self) -> bool {
        match self {
            Self::Code => true,
        }
    }
}

/// Context used by the `device_link.html` template
#[derive(Serialize, Default, Debug)]
pub struct DeviceLinkContext {
    form_state: FormState<DeviceLinkFormField>,
}

impl DeviceLinkContext {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the form state
    #[must_use]
    pub fn with_form_state(mut self, form_state: FormState<DeviceLinkFormField>) -> Self {
        self.form_state = form_state;
        self
    }
}

impl TemplateContext for DeviceLinkContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            Self::new(),
            Self::new().with_form_state(
                FormState::default()
                    .with_error_on_field(DeviceLinkFormField::Code, FieldError::Required),
            ),
        ])
    }
}

/// Context used by the `device_consent.html` template
#[derive(Serialize, Debug)]
pub struct DeviceConsentContext {
    grant: DeviceCodeGrant,
    client: Client,
    matrix_user: MatrixUser,
}

impl DeviceConsentContext {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new(grant: DeviceCodeGrant, client: Client, matrix_user: MatrixUser) -> Self {
        Self {
            grant,
            client,
            matrix_user,
        }
    }
}

impl TemplateContext for DeviceConsentContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(Client::samples(now, rng)
            .into_iter()
            .map(|client|  {
                let grant = DeviceCodeGrant {
                    id: Ulid::from_datetime_with_source(now.into(), rng),
                    state: mas_data_model::DeviceCodeGrantState::Pending,
                    client_id: client.id,
                    scope: [OPENID].into_iter().collect(),
                    user_code: Alphanumeric.sample_string(rng, 6).to_uppercase(),
                    device_code: Alphanumeric.sample_string(rng, 32),
                    created_at: now - Duration::try_minutes(5).unwrap(),
                    expires_at: now + Duration::try_minutes(25).unwrap(),
                    ip_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned()),
                };
                Self {
                    grant,
                    client,
                    matrix_user: MatrixUser {
                        mxid: "@alice:example.com".to_owned(),
                        display_name: Some("Alice".to_owned()),
                    }
                }
            })
            .collect())
    }
}

/// Context used by the `account/deactivated.html` and `account/locked.html`
/// templates
#[derive(Serialize)]
pub struct AccountInactiveContext {
    user: User,
}

impl AccountInactiveContext {
    /// Constructs a new context with an existing linked user
    #[must_use]
    pub fn new(user: User) -> Self {
        Self { user }
    }
}

impl TemplateContext for AccountInactiveContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(
            User::samples(now, rng)
                .into_iter()
                .map(|user| AccountInactiveContext { user })
                .collect(),
        )
    }
}

/// Context used by the `device_name.txt` template
#[derive(Serialize)]
pub struct DeviceNameContext {
    client: Client,
    raw_user_agent: String,
}

impl DeviceNameContext {
    /// Constructs a new context with a client and user agent
    #[must_use]
    pub fn new(client: Client, user_agent: Option<String>) -> Self {
        Self {
            client,
            raw_user_agent: user_agent.unwrap_or_default(),
        }
    }
}

impl TemplateContext for DeviceNameContext {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(Client::samples(now, rng)
            .into_iter()
            .map(|client| DeviceNameContext {
                client,
                raw_user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned(),
            })
            .collect())
    }
}

/// Context used by the `form_post.html` template
#[derive(Serialize)]
pub struct FormPostContext<T> {
    redirect_uri: Option<Url>,
    params: T,
}

impl<T: TemplateContext> TemplateContext for FormPostContext<T> {
    fn sample<R: Rng>(
        now: chrono::DateTime<Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        let sample_params = T::sample(now, rng, locales);
        sample_params
            .into_iter()
            .map(|(k, params)| {
                (
                    k,
                    FormPostContext {
                        redirect_uri: "https://example.com/callback".parse().ok(),
                        params,
                    },
                )
            })
            .collect()
    }
}

impl<T> FormPostContext<T> {
    /// Constructs a context for the `form_post` response mode form for a given
    /// URL
    pub fn new_for_url(redirect_uri: Url, params: T) -> Self {
        Self {
            redirect_uri: Some(redirect_uri),
            params,
        }
    }

    /// Constructs a context for the `form_post` response mode form for the
    /// current URL
    pub fn new_for_current_url(params: T) -> Self {
        Self {
            redirect_uri: None,
            params,
        }
    }

    /// Add the language to the context
    ///
    /// This is usually implemented by the [`TemplateContext`] trait, but it is
    /// annoying to make it work because of the generic parameter
    pub fn with_language(self, lang: &DataLocale) -> WithLanguage<Self> {
        WithLanguage {
            lang: lang.to_string(),
            inner: self,
        }
    }
}

/// Context used by the `error.html` template
#[derive(Default, Serialize, Debug, Clone)]
pub struct ErrorContext {
    code: Option<&'static str>,
    description: Option<String>,
    details: Option<String>,
    lang: Option<String>,
}

impl std::fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(code) = &self.code {
            writeln!(f, "code: {code}")?;
        }
        if let Some(description) = &self.description {
            writeln!(f, "{description}")?;
        }

        if let Some(details) = &self.details {
            writeln!(f, "details: {details}")?;
        }

        Ok(())
    }
}

impl TemplateContext for ErrorContext {
    fn sample<R: Rng>(
        _now: chrono::DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            Self::new()
                .with_code("sample_error")
                .with_description("A fancy description".into())
                .with_details("Something happened".into()),
            Self::new().with_code("another_error"),
            Self::new(),
        ])
    }
}

impl ErrorContext {
    /// Constructs a context for the error page
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the error code to the context
    #[must_use]
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
        self
    }

    /// Add the error description to the context
    #[must_use]
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Add the error details to the context
    #[must_use]
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Add the language to the context
    #[must_use]
    pub fn with_language(mut self, lang: &DataLocale) -> Self {
        self.lang = Some(lang.to_string());
        self
    }

    /// Get the error code, if any
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        self.code
    }

    /// Get the description, if any
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the details, if any
    #[must_use]
    pub fn details(&self) -> Option<&str> {
        self.details.as_deref()
    }
}

/// Context used by the not found (`404.html`) template
#[derive(Serialize)]
pub struct NotFoundContext {
    method: String,
    version: String,
    uri: String,
}

impl NotFoundContext {
    /// Constructs a context for the not found page
    #[must_use]
    pub fn new(method: &Method, version: Version, uri: &Uri) -> Self {
        Self {
            method: method.to_string(),
            version: format!("{version:?}"),
            uri: uri.to_string(),
        }
    }
}

impl TemplateContext for NotFoundContext {
    fn sample<R: Rng>(
        _now: DateTime<Utc>,
        _rng: &mut R,
        _locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        sample_list(vec![
            Self::new(&Method::GET, Version::HTTP_11, &"/".parse().unwrap()),
            Self::new(&Method::POST, Version::HTTP_2, &"/foo/bar".parse().unwrap()),
            Self::new(
                &Method::PUT,
                Version::HTTP_10,
                &"/foo?bar=baz".parse().unwrap(),
            ),
        ])
    }
}
