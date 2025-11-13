// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use mas_data_model::{
    Device,
    personal::{
        PersonalAccessToken as DataModelPersonalAccessToken,
        session::{PersonalSession as DataModelPersonalSession, PersonalSessionOwner},
    },
};
use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

/// A resource, with a type and an ID
pub trait Resource {
    /// The type of the resource
    const KIND: &'static str;

    /// The canonical path prefix for this kind of resource
    const PATH: &'static str;

    /// The ID of the resource
    fn id(&self) -> Ulid;

    /// The canonical path for this resource
    ///
    /// This is the concatenation of the canonical path prefix and the ID
    fn path(&self) -> String {
        format!("{}/{}", Self::PATH, self.id())
    }
}

/// A user
#[derive(Serialize, JsonSchema)]
pub struct User {
    #[serde(skip)]
    id: Ulid,

    /// The username (localpart) of the user
    username: String,

    /// When the user was created
    created_at: DateTime<Utc>,

    /// When the user was locked. If null, the user is not locked.
    locked_at: Option<DateTime<Utc>>,

    /// When the user was deactivated. If null, the user is not deactivated.
    deactivated_at: Option<DateTime<Utc>>,

    /// Whether the user can request admin privileges.
    admin: bool,

    /// Whether the user was a guest before migrating to MAS,
    legacy_guest: bool,
}

impl User {
    /// Samples of users with different properties for examples in the schema
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                admin: false,
                legacy_guest: false,
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                username: "bob".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                admin: true,
                legacy_guest: false,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                username: "charlie".to_owned(),
                created_at: DateTime::default(),
                locked_at: Some(DateTime::default()),
                deactivated_at: None,
                admin: false,
                legacy_guest: true,
            },
        ]
    }
}

impl From<mas_data_model::User> for User {
    fn from(user: mas_data_model::User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            created_at: user.created_at,
            locked_at: user.locked_at,
            deactivated_at: user.deactivated_at,
            admin: user.can_request_admin,
            legacy_guest: user.is_guest,
        }
    }
}

impl Resource for User {
    const KIND: &'static str = "user";
    const PATH: &'static str = "/api/admin/v1/users";

    fn id(&self) -> Ulid {
        self.id
    }
}

/// An email address for a user
#[derive(Serialize, JsonSchema)]
pub struct UserEmail {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// The ID of the user who owns this email address
    #[schemars(with = "super::schema::Ulid")]
    user_id: Ulid,

    /// The email address
    email: String,
}

impl Resource for UserEmail {
    const KIND: &'static str = "user-email";
    const PATH: &'static str = "/api/admin/v1/user-emails";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl From<mas_data_model::UserEmail> for UserEmail {
    fn from(value: mas_data_model::UserEmail) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            user_id: value.user_id,
            email: value.email,
        }
    }
}

impl UserEmail {
    pub fn samples() -> [Self; 1] {
        [Self {
            id: Ulid::from_bytes([0x01; 16]),
            created_at: DateTime::default(),
            user_id: Ulid::from_bytes([0x02; 16]),
            email: "alice@example.com".to_owned(),
        }]
    }
}

/// A compatibility session for legacy clients
#[derive(Serialize, JsonSchema)]
pub struct CompatSession {
    #[serde(skip)]
    pub id: Ulid,

    /// The ID of the user that owns this session
    #[schemars(with = "super::schema::Ulid")]
    pub user_id: Ulid,

    /// The Matrix device ID of this session
    #[schemars(with = "super::schema::Device")]
    pub device_id: Option<Device>,

    /// The ID of the user session that started this session, if any
    #[schemars(with = "super::schema::Ulid")]
    pub user_session_id: Option<Ulid>,

    /// The redirect URI used to login in the client, if it was an SSO login
    pub redirect_uri: Option<Url>,

    /// The time this session was created
    pub created_at: DateTime<Utc>,

    /// The user agent string that started this session, if any
    pub user_agent: Option<String>,

    /// The time this session was last active
    pub last_active_at: Option<DateTime<Utc>>,

    /// The last IP address recorded for this session
    pub last_active_ip: Option<std::net::IpAddr>,

    /// The time this session was finished
    pub finished_at: Option<DateTime<Utc>>,

    /// The user-provided name, if any
    pub human_name: Option<String>,
}

impl
    From<(
        mas_data_model::CompatSession,
        Option<mas_data_model::CompatSsoLogin>,
    )> for CompatSession
{
    fn from(
        (session, sso_login): (
            mas_data_model::CompatSession,
            Option<mas_data_model::CompatSsoLogin>,
        ),
    ) -> Self {
        let finished_at = session.finished_at();
        Self {
            id: session.id,
            user_id: session.user_id,
            device_id: session.device,
            user_session_id: session.user_session_id,
            redirect_uri: sso_login.map(|sso| sso.redirect_uri),
            created_at: session.created_at,
            user_agent: session.user_agent,
            last_active_at: session.last_active_at,
            last_active_ip: session.last_active_ip,
            finished_at,
            human_name: session.human_name,
        }
    }
}

impl Resource for CompatSession {
    const KIND: &'static str = "compat-session";
    const PATH: &'static str = "/api/admin/v1/compat-sessions";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl CompatSession {
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                user_id: Ulid::from_bytes([0x01; 16]),
                device_id: Some("AABBCCDDEE".to_owned().into()),
                user_session_id: Some(Ulid::from_bytes([0x11; 16])),
                redirect_uri: Some("https://example.com/redirect".parse().unwrap()),
                created_at: DateTime::default(),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some([1, 2, 3, 4].into()),
                finished_at: None,
                human_name: Some("Laptop".to_owned()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                user_id: Ulid::from_bytes([0x01; 16]),
                device_id: Some("FFGGHHIIJJ".to_owned().into()),
                user_session_id: Some(Ulid::from_bytes([0x12; 16])),
                redirect_uri: None,
                created_at: DateTime::default(),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some([1, 2, 3, 4].into()),
                finished_at: Some(DateTime::default()),
                human_name: None,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                user_id: Ulid::from_bytes([0x01; 16]),
                device_id: None,
                user_session_id: None,
                redirect_uri: None,
                created_at: DateTime::default(),
                user_agent: None,
                last_active_at: None,
                last_active_ip: None,
                finished_at: None,
                human_name: None,
            },
        ]
    }
}

/// A OAuth 2.0 session
#[derive(Serialize, JsonSchema)]
pub struct OAuth2Session {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// When the session was finished
    finished_at: Option<DateTime<Utc>>,

    /// The ID of the user who owns the session
    #[schemars(with = "Option<super::schema::Ulid>")]
    user_id: Option<Ulid>,

    /// The ID of the browser session which started this session
    #[schemars(with = "Option<super::schema::Ulid>")]
    user_session_id: Option<Ulid>,

    /// The ID of the client which requested this session
    #[schemars(with = "super::schema::Ulid")]
    client_id: Ulid,

    /// The scope granted for this session
    scope: String,

    /// The user agent string of the client which started this session
    user_agent: Option<String>,

    /// The last time the session was active
    last_active_at: Option<DateTime<Utc>>,

    /// The last IP address used by the session
    last_active_ip: Option<IpAddr>,

    /// The user-provided name, if any
    human_name: Option<String>,
}

impl From<mas_data_model::Session> for OAuth2Session {
    fn from(session: mas_data_model::Session) -> Self {
        Self {
            id: session.id,
            created_at: session.created_at,
            finished_at: session.finished_at(),
            user_id: session.user_id,
            user_session_id: session.user_session_id,
            client_id: session.client_id,
            scope: session.scope.to_string(),
            user_agent: session.user_agent,
            last_active_at: session.last_active_at,
            last_active_ip: session.last_active_ip,
            human_name: session.human_name,
        }
    }
}

impl OAuth2Session {
    /// Samples of OAuth 2.0 sessions
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: Some(Ulid::from_bytes([0x02; 16])),
                user_session_id: Some(Ulid::from_bytes([0x03; 16])),
                client_id: Ulid::from_bytes([0x04; 16]),
                scope: "openid".to_owned(),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
                human_name: Some("Laptop".to_owned()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: None,
                user_session_id: None,
                client_id: Ulid::from_bytes([0x05; 16]),
                scope: "urn:mas:admin".to_owned(),
                user_agent: None,
                last_active_at: None,
                last_active_ip: None,
                human_name: None,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                created_at: DateTime::default(),
                finished_at: Some(DateTime::default()),
                user_id: Some(Ulid::from_bytes([0x04; 16])),
                user_session_id: Some(Ulid::from_bytes([0x05; 16])),
                client_id: Ulid::from_bytes([0x06; 16]),
                scope: "urn:matrix:client:api:*".to_owned(),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
                human_name: None,
            },
        ]
    }
}

impl Resource for OAuth2Session {
    const KIND: &'static str = "oauth2-session";
    const PATH: &'static str = "/api/admin/v1/oauth2-sessions";

    fn id(&self) -> Ulid {
        self.id
    }
}

/// The browser (cookie) session for a user
#[derive(Serialize, JsonSchema)]
pub struct UserSession {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// When the session was finished
    finished_at: Option<DateTime<Utc>>,

    /// The ID of the user who owns the session
    #[schemars(with = "super::schema::Ulid")]
    user_id: Ulid,

    /// The user agent string of the client which started this session
    user_agent: Option<String>,

    /// The last time the session was active
    last_active_at: Option<DateTime<Utc>>,

    /// The last IP address used by the session
    last_active_ip: Option<IpAddr>,
}

impl From<mas_data_model::BrowserSession> for UserSession {
    fn from(value: mas_data_model::BrowserSession) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            finished_at: value.finished_at,
            user_id: value.user.id,
            user_agent: value.user_agent,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip,
        }
    }
}

impl UserSession {
    /// Samples of user sessions
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: Ulid::from_bytes([0x02; 16]),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                created_at: DateTime::default(),
                finished_at: None,
                user_id: Ulid::from_bytes([0x03; 16]),
                user_agent: None,
                last_active_at: None,
                last_active_ip: None,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                created_at: DateTime::default(),
                finished_at: Some(DateTime::default()),
                user_id: Ulid::from_bytes([0x04; 16]),
                user_agent: Some("Mozilla/5.0".to_owned()),
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("127.0.0.1".parse().unwrap()),
            },
        ]
    }
}

impl Resource for UserSession {
    const KIND: &'static str = "user-session";
    const PATH: &'static str = "/api/admin/v1/user-sessions";

    fn id(&self) -> Ulid {
        self.id
    }
}

/// An upstream OAuth 2.0 link
#[derive(Serialize, JsonSchema)]
pub struct UpstreamOAuthLink {
    #[serde(skip)]
    id: Ulid,

    /// When the object was created
    created_at: DateTime<Utc>,

    /// The ID of the provider
    #[schemars(with = "super::schema::Ulid")]
    provider_id: Ulid,

    /// The subject of the upstream account, unique per provider
    subject: String,

    /// The ID of the user who owns this link, if any
    #[schemars(with = "Option<super::schema::Ulid>")]
    user_id: Option<Ulid>,

    /// A human-readable name of the upstream account
    human_account_name: Option<String>,
}

impl Resource for UpstreamOAuthLink {
    const KIND: &'static str = "upstream-oauth-link";
    const PATH: &'static str = "/api/admin/v1/upstream-oauth-links";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl From<mas_data_model::UpstreamOAuthLink> for UpstreamOAuthLink {
    fn from(value: mas_data_model::UpstreamOAuthLink) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            provider_id: value.provider_id,
            subject: value.subject,
            user_id: value.user_id,
            human_account_name: value.human_account_name,
        }
    }
}

impl UpstreamOAuthLink {
    /// Samples of upstream OAuth 2.0 links
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                created_at: DateTime::default(),
                provider_id: Ulid::from_bytes([0x02; 16]),
                subject: "john-42".to_owned(),
                user_id: Some(Ulid::from_bytes([0x03; 16])),
                human_account_name: Some("john.doe@example.com".to_owned()),
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                created_at: DateTime::default(),
                provider_id: Ulid::from_bytes([0x03; 16]),
                subject: "jane-123".to_owned(),
                user_id: None,
                human_account_name: None,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                created_at: DateTime::default(),
                provider_id: Ulid::from_bytes([0x04; 16]),
                subject: "bob@social.example.com".to_owned(),
                user_id: Some(Ulid::from_bytes([0x05; 16])),
                human_account_name: Some("bob".to_owned()),
            },
        ]
    }
}

/// The policy data
#[derive(Serialize, JsonSchema)]
pub struct PolicyData {
    #[serde(skip)]
    id: Ulid,

    /// The creation date of the policy data
    created_at: DateTime<Utc>,

    /// The policy data content
    data: serde_json::Value,
}

impl From<mas_data_model::PolicyData> for PolicyData {
    fn from(policy_data: mas_data_model::PolicyData) -> Self {
        Self {
            id: policy_data.id,
            created_at: policy_data.created_at,
            data: policy_data.data,
        }
    }
}

impl Resource for PolicyData {
    const KIND: &'static str = "policy-data";
    const PATH: &'static str = "/api/admin/v1/policy-data";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl PolicyData {
    /// Samples of policy data
    pub fn samples() -> [Self; 1] {
        [Self {
            id: Ulid::from_bytes([0x01; 16]),
            created_at: DateTime::default(),
            data: serde_json::json!({
                "hello": "world",
                "foo": 42,
                "bar": true
            }),
        }]
    }
}

/// A registration token
#[derive(Serialize, JsonSchema)]
pub struct UserRegistrationToken {
    #[serde(skip)]
    id: Ulid,

    /// The token string
    token: String,

    /// Whether the token is valid
    valid: bool,

    /// Maximum number of times this token can be used
    usage_limit: Option<u32>,

    /// Number of times this token has been used
    times_used: u32,

    /// When the token was created
    created_at: DateTime<Utc>,

    /// When the token was last used. If null, the token has never been used.
    last_used_at: Option<DateTime<Utc>>,

    /// When the token expires. If null, the token never expires.
    expires_at: Option<DateTime<Utc>>,

    /// When the token was revoked. If null, the token is not revoked.
    revoked_at: Option<DateTime<Utc>>,
}

impl UserRegistrationToken {
    pub fn new(token: mas_data_model::UserRegistrationToken, now: DateTime<Utc>) -> Self {
        Self {
            id: token.id,
            valid: token.is_valid(now),
            token: token.token,
            usage_limit: token.usage_limit,
            times_used: token.times_used,
            created_at: token.created_at,
            last_used_at: token.last_used_at,
            expires_at: token.expires_at,
            revoked_at: token.revoked_at,
        }
    }
}

impl Resource for UserRegistrationToken {
    const KIND: &'static str = "user-registration_token";
    const PATH: &'static str = "/api/admin/v1/user-registration-tokens";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl UserRegistrationToken {
    /// Samples of registration tokens
    pub fn samples() -> [Self; 2] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                token: "abc123def456".to_owned(),
                valid: true,
                usage_limit: Some(10),
                times_used: 5,
                created_at: DateTime::default(),
                last_used_at: Some(DateTime::default()),
                expires_at: Some(DateTime::default() + chrono::Duration::days(30)),
                revoked_at: None,
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                token: "xyz789abc012".to_owned(),
                valid: false,
                usage_limit: None,
                times_used: 0,
                created_at: DateTime::default(),
                last_used_at: None,
                expires_at: None,
                revoked_at: Some(DateTime::default()),
            },
        ]
    }
}

/// An upstream OAuth 2.0 provider
#[derive(Serialize, JsonSchema)]
pub struct UpstreamOAuthProvider {
    #[serde(skip)]
    id: Ulid,

    /// The OIDC issuer of the provider
    issuer: Option<String>,

    /// A human-readable name for the provider
    human_name: Option<String>,

    /// A brand identifier, e.g. "apple" or "google"
    brand_name: Option<String>,

    /// When the provider was created
    created_at: DateTime<Utc>,

    /// When the provider was disabled. If null, the provider is enabled.
    disabled_at: Option<DateTime<Utc>>,
}

impl From<mas_data_model::UpstreamOAuthProvider> for UpstreamOAuthProvider {
    fn from(provider: mas_data_model::UpstreamOAuthProvider) -> Self {
        Self {
            id: provider.id,
            issuer: provider.issuer,
            human_name: provider.human_name,
            brand_name: provider.brand_name,
            created_at: provider.created_at,
            disabled_at: provider.disabled_at,
        }
    }
}

impl Resource for UpstreamOAuthProvider {
    const KIND: &'static str = "upstream-oauth-provider";
    const PATH: &'static str = "/api/admin/v1/upstream-oauth-providers";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl UpstreamOAuthProvider {
    /// Samples of upstream OAuth 2.0 providers
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_bytes([0x01; 16]),
                issuer: Some("https://accounts.google.com".to_owned()),
                human_name: Some("Google".to_owned()),
                brand_name: Some("google".to_owned()),
                created_at: DateTime::default(),
                disabled_at: None,
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                issuer: Some("https://appleid.apple.com".to_owned()),
                human_name: Some("Apple ID".to_owned()),
                brand_name: Some("apple".to_owned()),
                created_at: DateTime::default(),
                disabled_at: Some(DateTime::default()),
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                issuer: None,
                human_name: Some("Custom OAuth Provider".to_owned()),
                brand_name: None,
                created_at: DateTime::default(),
                disabled_at: None,
            },
        ]
    }
}
<<<<<<< HEAD
=======

/// An error that shouldn't happen in practice, but suggests database
/// inconsistency.
#[derive(Debug, Error)]
#[error(
    "personal session {session_id} in inconsistent state: not revoked but no valid access token"
)]
pub struct InconsistentPersonalSession {
    pub session_id: Ulid,
}

// Note: we don't expose a separate concept of personal access tokens to the
// admin API; we merge the relevant attributes into the personal session.
/// A personal session (session using personal access tokens)
#[derive(Serialize, JsonSchema)]
pub struct PersonalSession {
    #[serde(skip)]
    id: Ulid,

    /// When the session was created
    created_at: DateTime<Utc>,

    /// When the session was revoked, if applicable
    revoked_at: Option<DateTime<Utc>>,

    /// The ID of the user who owns this session (if user-owned)
    #[schemars(with = "Option<super::schema::Ulid>")]
    owner_user_id: Option<Ulid>,

    /// The ID of the `OAuth2` client that owns this session (if client-owned)
    #[schemars(with = "Option<super::schema::Ulid>")]
    owner_client_id: Option<Ulid>,

    /// The ID of the user that the session acts on behalf of
    #[schemars(with = "super::schema::Ulid")]
    actor_user_id: Ulid,

    /// Human-readable name for the session
    human_name: String,

    /// `OAuth2` scopes for this session
    scope: String,

    /// When the session was last active
    last_active_at: Option<DateTime<Utc>>,

    /// IP address of last activity
    last_active_ip: Option<IpAddr>,

    /// When the current token for this session expires.
    /// The session will need to be regenerated, producing a new access token,
    /// after this time.
    /// None if the current token won't expire or if the session is revoked.
    expires_at: Option<DateTime<Utc>>,

    /// The actual access token (only returned on creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
}

impl
    TryFrom<(
        DataModelPersonalSession,
        Option<DataModelPersonalAccessToken>,
    )> for PersonalSession
{
    type Error = InconsistentPersonalSession;

    fn try_from(
        (session, token): (
            DataModelPersonalSession,
            Option<DataModelPersonalAccessToken>,
        ),
    ) -> Result<Self, InconsistentPersonalSession> {
        let expires_at = if let Some(token) = token {
            token.expires_at
        } else {
            if !session.is_revoked() {
                // No active token, but the session is not revoked.
                return Err(InconsistentPersonalSession {
                    session_id: session.id,
                });
            }
            None
        };

        let (owner_user_id, owner_client_id) = match session.owner {
            PersonalSessionOwner::User(id) => (Some(id), None),
            PersonalSessionOwner::OAuth2Client(id) => (None, Some(id)),
        };

        Ok(Self {
            id: session.id,
            created_at: session.created_at,
            revoked_at: session.revoked_at(),
            owner_user_id,
            owner_client_id,
            actor_user_id: session.actor_user_id,
            human_name: session.human_name,
            scope: session.scope.to_string(),
            last_active_at: session.last_active_at,
            last_active_ip: session.last_active_ip,
            expires_at,
            // If relevant, the caller will populate using `with_token` afterwards.
            access_token: None,
        })
    }
}

impl Resource for PersonalSession {
    const KIND: &'static str = "personal-session";
    const PATH: &'static str = "/api/admin/v1/personal-sessions";

    fn id(&self) -> Ulid {
        self.id
    }
}

impl PersonalSession {
    /// Sample personal sessions for documentation/testing
    pub fn samples() -> [Self; 3] {
        [
            Self {
                id: Ulid::from_string("01FSHN9AG0AJ6AC5HQ9X6H4RP4").unwrap(),
                created_at: DateTime::from_timestamp(1_642_338_000, 0).unwrap(), /* 2022-01-16T14:
                                                                                  * 40:00Z */
                revoked_at: None,
                owner_user_id: Some(Ulid::from_string("01FSHN9AG0MZAA6S4AF7CTV32E").unwrap()),
                owner_client_id: None,
                actor_user_id: Ulid::from_string("01FSHN9AG0MZAA6S4AF7CTV32E").unwrap(),
                human_name: "Alice's Development Token".to_owned(),
                scope: "openid urn:matrix:org.matrix.msc2967.client:api:*".to_owned(),
                last_active_at: Some(DateTime::from_timestamp(1_642_347_000, 0).unwrap()), /* 2022-01-16T17:10:00Z */
                last_active_ip: Some("192.168.1.100".parse().unwrap()),
                expires_at: None,
                access_token: None,
            },
            Self {
                id: Ulid::from_string("01FSHN9AG0BJ6AC5HQ9X6H4RP5").unwrap(),
                created_at: DateTime::from_timestamp(1_642_338_060, 0).unwrap(), /* 2022-01-16T14:
                                                                                  * 41:00Z */
                revoked_at: Some(DateTime::from_timestamp(1_642_350_000, 0).unwrap()), /* 2022-01-16T18:00:00Z */
                owner_user_id: Some(Ulid::from_string("01FSHN9AG0NZAA6S4AF7CTV32F").unwrap()),
                owner_client_id: None,
                actor_user_id: Ulid::from_string("01FSHN9AG0NZAA6S4AF7CTV32F").unwrap(),
                human_name: "Bob's Mobile App".to_owned(),
                scope: "openid".to_owned(),
                last_active_at: Some(DateTime::from_timestamp(1_642_349_000, 0).unwrap()), /* 2022-01-16T17:43:20Z */
                last_active_ip: Some("10.0.0.50".parse().unwrap()),
                expires_at: None,
                access_token: None,
            },
            Self {
                id: Ulid::from_string("01FSHN9AG0CJ6AC5HQ9X6H4RP6").unwrap(),
                created_at: DateTime::from_timestamp(1_642_338_120, 0).unwrap(), /* 2022-01-16T14:
                                                                                  * 42:00Z */
                revoked_at: None,
                owner_user_id: None,
                owner_client_id: Some(Ulid::from_string("01FSHN9AG0DJ6AC5HQ9X6H4RP7").unwrap()),
                actor_user_id: Ulid::from_string("01FSHN9AG0MZAA6S4AF7CTV32E").unwrap(),
                human_name: "CI/CD Pipeline Token".to_owned(),
                scope: "openid urn:mas:admin".to_owned(),
                last_active_at: Some(DateTime::from_timestamp(1_642_348_000, 0).unwrap()), /* 2022-01-16T17:26:40Z */
                last_active_ip: Some("203.0.113.10".parse().unwrap()),
                expires_at: Some(DateTime::from_timestamp(1_642_999_000, 0).unwrap()),
                access_token: None,
            },
        ]
    }

    /// Add the actual token value (for use in creation responses)
    pub fn with_token(mut self, access_token: String) -> Self {
        self.access_token = Some(access_token);
        self
    }
}
>>>>>>> v1.6.0
