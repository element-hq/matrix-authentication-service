// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
// Copyright 2025 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashSet, str::FromStr};

use aide::{NoApi, OperationIo, transform::TransformOperation};
use axum::{Json, extract::State, response::IntoResponse};
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use lettre::Address;
use mas_axum_utils::record_error;
use mas_data_model::{BoxRng, is_username_template};
use mas_policy::{EvaluationError, EvaluationResult, Policy};
use mas_router::UrlBuilder;
use mas_storage::user::UserRegistrationTokenParams;
use rand::distr::{Alphanumeric, SampleString};
use schemars::JsonSchema;
use serde::Deserialize;
use url::Url;

use crate::{
    admin::{
        call_context::CallContext,
        model::UserRegistrationToken,
        response::{ErrorResponse, SingleResponse},
    },
    impl_from_error_for_route, username_template,
};

#[derive(Debug, thiserror::Error, OperationIo)]
#[aide(output_with = "Json<ErrorResponse>")]
pub enum RouteError {
    #[error("A registration token with the same token already exists")]
    Conflict(Box<mas_data_model::UserRegistrationToken>),

    #[error("Continue URL {0:?} is not an ASCII http or https URL")]
    ContinueUrlNotValid(String),

    #[error("Email {email:?} is not valid")]
    EmailNotValid {
        email: String,

        #[source]
        source: lettre::address::AddressError,
    },

    #[error("`email` and `allowed_emails` can't both be set")]
    EmailAndAllowedEmails,

    #[error("`allowed_emails` needs `passwordless`")]
    AllowedEmailsNotPasswordless,

    #[error(transparent)]
    InvalidAllowedEmails(#[from] AllowedEmailsError),

    #[error("Username template {template:?} is not valid")]
    InvalidUsernameTemplate {
        template: String,

        #[source]
        source: minijinja::Error,
    },

    #[error(transparent)]
    NotAllowed(#[from] NotAllowed),

    #[error("Username {0:?} is already taken")]
    UsernameTaken(String),

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::EvaluationError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let error = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let status = match self {
            Self::Conflict(_) | Self::UsernameTaken(_) => StatusCode::CONFLICT,
            Self::ContinueUrlNotValid(_)
            | Self::EmailNotValid { .. }
            | Self::EmailAndAllowedEmails
            | Self::AllowedEmailsNotPasswordless
            | Self::InvalidAllowedEmails(_)
            | Self::InvalidUsernameTemplate { .. }
            | Self::NotAllowed(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, sentry_event_id, Json(error)).into_response()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Not allowed by the registration policy: {}", .0.join("; "))]
pub struct NotAllowed(Vec<String>);

impl NotAllowed {
    /// An error naming `violations`, sorted, if there are any
    pub(super) fn check(mut violations: Vec<String>) -> Result<(), Self> {
        if violations.is_empty() {
            return Ok(());
        }
        violations.sort();
        Err(Self(violations))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AllowedEmailsError {
    #[error("`allowed_emails` must not be empty")]
    Empty,

    #[error("Email {email:?} is not valid")]
    EmailNotValid {
        email: String,

        #[source]
        source: lettre::address::AddressError,
    },
}

/// # JSON payload for the `POST /api/admin/v1/user-registration-tokens`
#[derive(Deserialize, JsonSchema)]
#[serde(rename = "AddUserRegistrationTokenRequest")]
pub struct Request {
    /// The token string. If not provided, a random token will be generated.
    /// Anyone holding the token can open its invite URL, which shows the
    /// username and email address it imposes, so a token provided here must be
    /// as hard to guess as a generated one.
    token: Option<String>,

    /// Maximum number of times this token can be used. If not provided, the
    /// token can be used an unlimited number of times.
    usage_limit: Option<u32>,

    /// When the token expires. If not provided, the token never expires.
    expires_at: Option<DateTime<Utc>>,

    /// A username to impose on the registering user. If set, the user cannot
    /// choose their own username. A value with `{` is a minijinja template:
    /// registering through the token's `/register?token=…` link renders it
    /// with `random`, 32 random lowercase letters and digits, without showing
    /// the user the name. A template token works only through that link: the
    /// registration token step refuses it. A template must render with a
    /// sample `random`, and the result pass the registration policy. A
    /// username which isn't a template must pass the policy and must not be
    /// taken.
    #[schemars(example = &"user-{{ random }}")]
    username: Option<String>,

    /// An email address to impose on the registering user. If set, the user
    /// cannot choose their own email. It must pass the registration policy.
    email: Option<String>,

    /// The email addresses the registering user must use one of, in place of
    /// `email`, for a `passwordless` token. If set, it must not be empty, and
    /// each address must pass the registration policy. Repeats of an address
    /// in another case are dropped.
    #[schemars(example = &["alice@example.com", "bob@example.com"])]
    allowed_emails: Option<Vec<String>>,

    /// Whether registering with this token skips the password step. The user's
    /// identity is then established by verifying their email address.
    #[serde(default)]
    passwordless: bool,

    /// Where to send the user once they have registered or signed in through
    /// the token's link. It must be an http or https URL, with anything but
    /// visible ASCII characters percent-encoded, and is used as given: it can
    /// be a page of any client, or one that lets the user pick a client.
    /// Whoever holds the link can reach this URL without signing in, even
    /// once the token is used, expired or revoked.
    #[schemars(url, example = &"https://app.example.com/#/room/%21room%3Aexample.com")]
    continue_url: Option<String>,
}

pub fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .id("addUserRegistrationToken")
        .summary("Create a new user registration token")
        .tag("user-registration-token")
        .response_with::<201, Json<SingleResponse<UserRegistrationToken>>, _>(|t| {
            let [sample, ..] = UserRegistrationToken::samples();
            let response = SingleResponse::new_canonical(sample);
            t.description("A new user registration token was created")
                .example(response)
        })
        .response_with::<400, RouteError, _>(|t| {
            let response = ErrorResponse::from_error(&RouteError::ContinueUrlNotValid(
                "app.example.com".to_owned(),
            ));
            t.description(
                "The continue URL, an email or the username template is not valid, the \
                 registration policy refuses an email or the username, `allowed_emails` is \
                 empty, or it is set with `email` or without `passwordless`",
            )
            .example(response)
        })
        .response_with::<409, RouteError, _>(|t| {
            let response =
                ErrorResponse::from_error(&RouteError::UsernameTaken("alice".to_owned()));
            t.description("A token with the same token already exists, or the username is taken")
                .example(response)
        })
}

/// The violations of a refused policy evaluation
fn violations(result: EvaluationResult) -> Vec<String> {
    result
        .violations
        .into_iter()
        .map(|violation| match violation.field {
            Some(field) => format!("{field}: {}", violation.msg),
            None => violation.msg,
        })
        .collect()
}

/// `emails`, each checked to be an address, without the repeats of an address
/// in another case
pub(super) fn parse_allowed_emails(
    mut emails: Vec<String>,
) -> Result<Vec<String>, AllowedEmailsError> {
    for email in &emails {
        if let Err(source) = Address::from_str(email) {
            return Err(AllowedEmailsError::EmailNotValid {
                email: email.clone(),
                source,
            });
        }
    }

    let mut seen = HashSet::new();
    emails.retain(|email| seen.insert(email.to_ascii_lowercase()));
    if emails.is_empty() {
        return Err(AllowedEmailsError::Empty);
    }

    Ok(emails)
}

/// The email policy's violations for each of `emails`, naming the address
pub(super) async fn allowed_emails_violations(
    policy: &mut Policy,
    emails: &[String],
) -> Result<Vec<String>, EvaluationError> {
    let mut violations = Vec::new();
    for email in emails {
        let result = policy
            .evaluate_email(mas_policy::EmailInput {
                email,
                requester: mas_policy::Requester::default(),
            })
            .await?;
        violations.extend(
            result
                .violations
                .into_iter()
                .map(|violation| format!("{email}: {}", violation.msg)),
        );
    }
    Ok(violations)
}

#[tracing::instrument(name = "handler.admin.v1.user_registration_tokens.post", skip_all)]
pub async fn handler(
    CallContext {
        mut repo, clock, ..
    }: CallContext,
    State(url_builder): State<UrlBuilder>,
    NoApi(mut rng): NoApi<BoxRng>,
    NoApi(mut policy): NoApi<Policy>,
    Json(params): Json<Request>,
) -> Result<(StatusCode, Json<SingleResponse<UserRegistrationToken>>), RouteError> {
    // Web URLs only, so not an app's own scheme such as `matrix:`. The URL
    // goes in a `Location` header as given, where a browser resolves one
    // without `//` against MAS.
    if let Some(url) = &params.continue_url
        && !(url.bytes().all(|b| b.is_ascii_graphic())
            && (url.starts_with("http://") || url.starts_with("https://"))
            && Url::parse(url).is_ok())
    {
        return Err(RouteError::ContinueUrlNotValid(url.clone()));
    }

    if params.email.is_some() && params.allowed_emails.is_some() {
        return Err(RouteError::EmailAndAllowedEmails);
    }

    if params.allowed_emails.is_some() && !params.passwordless {
        return Err(RouteError::AllowedEmailsNotPasswordless);
    }

    if let Some(email) = &params.email
        && let Err(source) = Address::from_str(email)
    {
        return Err(RouteError::EmailNotValid {
            email: email.clone(),
            source,
        });
    }

    let allowed_emails = params
        .allowed_emails
        .map(parse_allowed_emails)
        .transpose()?;

    // A template is checked by rendering it with a sample, as the name it
    // renders to is only known when registering, which checks it again
    let template_sample = match params.username.as_deref() {
        Some(username) if is_username_template(username) => Some(
            username_template::render_sample(username).map_err(|source| {
                RouteError::InvalidUsernameTemplate {
                    template: username.to_owned(),
                    source,
                }
            })?,
        ),
        _ => None,
    };

    // The same input as `POST /register` in `views/register/password.rs`,
    // which also evaluates a passwordless registration as `Password`. The
    // request comes from an admin client, not the user registering.
    let result = match (
        template_sample.as_deref().or(params.username.as_deref()),
        params.email.as_deref(),
    ) {
        (Some(username), email) => Some(
            policy
                .evaluate_register(mas_policy::RegisterInput {
                    registration_method: mas_policy::RegistrationMethod::Password,
                    username,
                    email,
                    requester: mas_policy::Requester::default(),
                })
                .await?,
        ),
        (None, Some(email)) => Some(
            policy
                .evaluate_email(mas_policy::EmailInput {
                    email,
                    requester: mas_policy::Requester::default(),
                })
                .await?,
        ),
        (None, None) => None,
    };
    let mut refused = result.map(violations).unwrap_or_default();
    if let Some(allowed_emails) = &allowed_emails {
        refused.extend(allowed_emails_violations(&mut policy, allowed_emails).await?);
    }
    NotAllowed::check(refused)?;

    // The holder of a token pinned to a name someone else already has can
    // never finish registering. An email address already in use is not
    // refused: a client minting tokens for addresses its users typed would
    // tell them which addresses have an account
    if let Some(username) = &params.username
        && template_sample.is_none()
        && repo.user().exists(username).await?
    {
        return Err(RouteError::UsernameTaken(username.clone()));
    }

    // Generate a random token if none was provided
    let token = params
        .token
        .unwrap_or_else(|| Alphanumeric.sample_string(&mut rng, 12));

    // See if we have an existing token with the same token
    let existing_token = repo.user_registration_token().find_by_token(&token).await?;
    if let Some(existing_token) = existing_token {
        return Err(RouteError::Conflict(Box::new(existing_token)));
    }

    let registration_token = repo
        .user_registration_token()
        .add(
            &mut rng,
            &clock,
            UserRegistrationTokenParams {
                token,
                usage_limit: params.usage_limit,
                expires_at: params.expires_at,
                username: params.username,
                email: params.email,
                allowed_emails,
                passwordless: params.passwordless,
                continue_url: params.continue_url,
            },
        )
        .await?;

    repo.save().await?;

    Ok((
        StatusCode::CREATED,
        Json(SingleResponse::new_canonical(UserRegistrationToken::new(
            registration_token,
            clock.now(),
            &url_builder,
        ))),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use insta::assert_json_snapshot;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_token_123"
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    /// The token travels in the query string of the invite URL, so one with
    /// reserved characters comes back percent-encoded
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_invite_url_encoding(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({ "token": "a token&more" }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();

        assert_eq!(
            body["data"]["attributes"]["invite_url"],
            "https://example.com/register?token=a+token%26more"
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_auto_token(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "usage_limit": 1
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0QMGC989M0XSFVF2X",
            "attributes": {
              "token": "42oTpLoieH5I",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": 1,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=42oTpLoieH5I"
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0QMGC989M0XSFVF2X"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_passwordless(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "invite_alice",
                "username": "alice",
                "email": "alice@example.com",
                "passwordless": true,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "invite_alice",
              "valid": true,
              "username": "alice",
              "email": "alice@example.com",
              "allowed_emails": null,
              "passwordless": true,
              "continue_url": null,
              "usage_limit": null,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=invite_alice"
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_continue_url(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let mut ids = Vec::new();
        for (name, continue_url) in [
            (
                "with_url",
                Some("https://app.example.com/#/room/%21room%3Aexample.com?via=example.com"),
            ),
            ("no_url", None),
        ] {
            let request = Request::post("/api/admin/v1/user-registration-tokens")
                .bearer(&token)
                .json(serde_json::json!({ "token": name, "continue_url": continue_url }));
            let response = state.request(request).await;
            response.assert_status(StatusCode::CREATED);
            let body: serde_json::Value = response.json();
            assert_eq!(
                body["data"]["attributes"]["continue_url"],
                serde_json::json!(continue_url)
            );
            let id = body["data"]["id"].as_str().unwrap().to_owned();

            let request = Request::get(format!("/api/admin/v1/user-registration-tokens/{id}"))
                .bearer(&token)
                .empty();
            let response = state.request(request).await;
            response.assert_status(StatusCode::OK);
            let body: serde_json::Value = response.json();
            assert_eq!(
                body["data"]["attributes"]["continue_url"],
                serde_json::json!(continue_url)
            );

            ids.push((id, continue_url));
        }

        let request = Request::get("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        for (id, continue_url) in ids {
            let listed = body["data"]
                .as_array()
                .unwrap()
                .iter()
                .find(|token| token["id"] == id)
                .unwrap();
            assert_eq!(
                listed["attributes"]["continue_url"],
                serde_json::json!(continue_url)
            );
        }
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_invalid_continue_url(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        for continue_url in [
            "app.example.com/#/room/%21room%3Aexample.com",
            "/#/room/%21room%3Aexample.com",
            "javascript:alert(1)",
            "matrix:roomid/room:example.com",
            "https://app.example.com/#/room/a b",
            "https://app.example.com/#/room/a\nb",
            "https://app.example.com/#/room/é",
            "https:app.example.com/#/room/a",
            "https:/app.example.com/#/room/a",
            "https://",
        ] {
            let request = Request::post("/api/admin/v1/user-registration-tokens")
                .bearer(&token)
                .json(serde_json::json!({ "continue_url": continue_url }));
            let response = state.request(request).await;
            response.assert_status(StatusCode::BAD_REQUEST);
            let body: serde_json::Value = response.json();
            assert_eq!(
                body["errors"][0]["title"],
                format!("Continue URL {continue_url:?} is not an ASCII http or https URL")
            );
        }
    }

    /// Post `body` and return the response's status and error titles
    async fn create_errors(
        state: &mut TestState,
        body: serde_json::Value,
    ) -> (StatusCode, Vec<String>) {
        let token = state.token_with_scope("urn:mas:admin").await;
        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(body);
        let response = state.request(request).await;
        let titles = serde_json::from_str::<serde_json::Value>(response.body())
            .ok()
            .and_then(|body| body["errors"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|error| error["title"].as_str().map(ToOwned::to_owned))
            .collect();
        (response.status(), titles)
    }

    /// Post `body` and return the response's status and first error title
    async fn create(state: &mut TestState, body: serde_json::Value) -> (StatusCode, String) {
        let (status, titles) = create_errors(state, body).await;
        (status, titles.into_iter().next().unwrap_or_default())
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_invalid_pins(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        let (status, title) =
            create(&mut state, serde_json::json!({ "email": "not-an-email" })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(title, r#"Email "not-an-email" is not valid"#);

        // The template's error comes first, then minijinja's render error
        for (username, source) in [
            ("user-{{ random", "syntax error"),
            ("user-{{ email }}", "undefined value"),
        ] {
            let (status, errors) =
                create_errors(&mut state, serde_json::json!({ "username": username })).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{username}");
            assert_eq!(
                errors[0],
                format!("Username template {username:?} is not valid")
            );
            assert!(errors[1].contains(source), "{errors:?}");
        }
    }

    /// A token stores and shows its allowed addresses, without the repeats of
    /// an address in another case
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_allowed_emails(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "username": "user-{{ random }}",
                "allowed_emails": ["Alice@Example.com", "bob@example.com", "alice@example.com"],
                "passwordless": true,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["data"]["attributes"]["allowed_emails"],
            serde_json::json!(["Alice@Example.com", "bob@example.com"])
        );

        let request = Request::get(format!(
            "/api/admin/v1/user-registration-tokens/{}",
            body["data"]["id"].as_str().unwrap()
        ))
        .bearer(&token)
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body: serde_json::Value = response.json();
        assert_eq!(
            body["data"]["attributes"]["allowed_emails"],
            serde_json::json!(["Alice@Example.com", "bob@example.com"])
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_invalid_allowed_emails(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        for (body, error) in [
            (
                serde_json::json!({ "allowed_emails": [], "passwordless": true }),
                "`allowed_emails` must not be empty",
            ),
            (
                serde_json::json!({
                    "allowed_emails": ["alice@example.com", "not-an-email"],
                    "passwordless": true,
                }),
                r#"Email "not-an-email" is not valid"#,
            ),
            (
                serde_json::json!({
                    "email": "alice@example.com",
                    "allowed_emails": ["alice@example.com"],
                }),
                "`email` and `allowed_emails` can't both be set",
            ),
            (
                serde_json::json!({ "allowed_emails": ["alice@example.com"] }),
                "`allowed_emails` needs `passwordless`",
            ),
        ] {
            let (status, title) = create(&mut state, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
            assert_eq!(title, error);
        }
    }

    /// A pinned email or username the registration policy refuses is a 400
    /// naming every violation. A template is checked by what it renders to
    /// with a sample.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_refused_by_policy(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/policy-data")
            .bearer(&token)
            .json(serde_json::json!({
                "data": {
                    "banned_domains": ["banned.example"],
                    "registration": {
                        "banned_usernames": { "literals": ["user-banned"], "prefixes": ["banned-"] },
                    },
                },
            }));
        state
            .request(request)
            .await
            .assert_status(StatusCode::CREATED);

        for (body, error) in [
            (
                serde_json::json!({ "email": "bob@banned.example" }),
                "Not allowed by the registration policy: email domain is banned",
            ),
            (
                serde_json::json!({ "email": "bob@banned.example", "username": "user-bob" }),
                "Not allowed by the registration policy: email: email domain is banned",
            ),
            (
                serde_json::json!({ "username": "user-banned" }),
                "Not allowed by the registration policy: username: username is banned",
            ),
            (
                serde_json::json!({ "email": "bob@banned.example", "username": "user-banned" }),
                "Not allowed by the registration policy: email: email domain is banned; username: username is banned",
            ),
            (
                serde_json::json!({
                    "allowed_emails": ["alice@example.com", "bob@banned.example"],
                    "passwordless": true,
                }),
                "Not allowed by the registration policy: bob@banned.example: email domain is banned",
            ),
            (
                serde_json::json!({
                    "allowed_emails": ["carol@banned.example", "bob@banned.example"],
                    "username": "user-banned",
                    "passwordless": true,
                }),
                "Not allowed by the registration policy: bob@banned.example: email domain is banned; carol@banned.example: email domain is banned; username: username is banned",
            ),
            (
                serde_json::json!({ "username": "banned-{{ random }}" }),
                "Not allowed by the registration policy: username: username is banned",
            ),
            (
                serde_json::json!({ "username": "User-{{ random }}" }),
                "Not allowed by the registration policy: username: username contains invalid characters",
            ),
            (
                serde_json::json!({ "username": "user-{random}" }),
                "Not allowed by the registration policy: username: username contains invalid characters",
            ),
        ] {
            let (status, title) = create(&mut state, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
            assert_eq!(title, error);
        }

        let (status, _) = create(
            &mut state,
            serde_json::json!({ "email": "bob@example.com", "username": "user-{{ random }}" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }

    /// A token pinned to a username nobody can register with is refused. A
    /// template is never taken, even by its sample's name or its own string.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_username_taken(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

        let mut repo = state.repository().await.unwrap();
        for username in [
            "alice",
            "user-a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5",
            "user-{{ random }}",
        ] {
            repo.user()
                .add(&mut state.rng(), &state.clock, username.to_owned())
                .await
                .unwrap();
        }
        repo.save().await.unwrap();

        let (status, title) = create(&mut state, serde_json::json!({ "username": "alice" })).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(title, r#"Username "alice" is already taken"#);

        let (status, _) = create(
            &mut state,
            serde_json::json!({ "token": "template", "username": "user-{{ random }}" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let mut repo = state.repository().await.unwrap();
        let token = repo
            .user_registration_token()
            .find_by_token("template")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.username.as_deref(), Some("user-{{ random }}"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_create_conflict(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();
        let token = state.token_with_scope("urn:mas:admin").await;

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let body: serde_json::Value = response.json();

        assert_json_snapshot!(body, @r#"
        {
          "data": {
            "type": "user-registration_token",
            "id": "01FSHN9AG0MZAA6S4AF7CTV32E",
            "attributes": {
              "token": "test_token_123",
              "valid": true,
              "username": null,
              "email": null,
              "allowed_emails": null,
              "passwordless": false,
              "continue_url": null,
              "usage_limit": 5,
              "times_used": 0,
              "created_at": "2022-01-16T14:40:00Z",
              "last_used_at": null,
              "expires_at": null,
              "revoked_at": null,
              "invite_url": "https://example.com/register?token=test_token_123"
            },
            "links": {
              "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
            }
          },
          "links": {
            "self": "/api/admin/v1/user-registration-tokens/01FSHN9AG0MZAA6S4AF7CTV32E"
          }
        }
        "#);

        let request = Request::post("/api/admin/v1/user-registration-tokens")
            .bearer(&token)
            .json(serde_json::json!({
                "token": "test_token_123",
                "usage_limit": 5
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CONFLICT);
    }
}
