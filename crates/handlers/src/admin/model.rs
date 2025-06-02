// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use mas_data_model::Device;
use schemars::JsonSchema;
use serde::Serialize;
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
            },
            Self {
                id: Ulid::from_bytes([0x02; 16]),
                username: "bob".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                admin: true,
            },
            Self {
                id: Ulid::from_bytes([0x03; 16]),
                username: "charlie".to_owned(),
                created_at: DateTime::default(),
                locked_at: Some(DateTime::default()),
                deactivated_at: None,
                admin: false,
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
                scope: "urn:matrix:org.matrix.msc2967.client:api:*".to_owned(),
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
