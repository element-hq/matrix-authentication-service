// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::{
    Context, Enum, ID, Object, SimpleObject,
    connection::{Connection, Edge, OpaqueCursor, query},
};
use mas_storage::{Pagination, user::UserFilter};

use crate::graphql::{
    UserId,
    model::{Cursor, NodeCursor, NodeType, PreloadedTotalCount, User},
    state::ContextExt as _,
};

/// Why a username is not available for registration.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum UsernameUnavailableReason {
    /// The username is already taken by an existing user in MAS.
    Taken,
    /// The username is reserved by the homeserver.
    ///
    /// Note that the homeserver may also reject the username at registration
    /// time for other reasons (e.g. Synapse's `M_USER_IN_USE`) that this
    /// query cannot predict, since it only checks availability, not all the
    /// homeserver's own registration rules.
    Reserved,
    /// The username does not pass the registration policy (e.g. it is too
    /// long, all-numeric, contains invalid characters, or is banned).
    ///
    /// See `violationCodes` for the specific reasons.
    Invalid,
}

/// The result of a username availability check.
#[derive(SimpleObject)]
struct UsernameAvailability {
    /// The username that was checked.
    username: String,
    /// Whether the username is available for registration.
    available: bool,
    /// If the username is not available, the reason why.
    reason: Option<UsernameUnavailableReason>,
    /// If the username is invalid, the list of policy violation codes (e.g.
    /// `username-too-long`, `username-all-numeric`, `username-banned`,
    /// `username-not-allowed`, `username-invalid-chars`), so that clients can
    /// localize the error message.
    violation_codes: Option<Vec<String>>,
}

#[derive(Default)]
pub struct UserQuery;

#[Object]
impl UserQuery {
    /// Fetch a user by its ID.
    pub async fn user(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<User>, async_graphql::Error> {
        let id = NodeType::User.extract_ulid(&id)?;

        let requester = ctx.requester();
        if !requester.is_owner_or_admin(&UserId(id)) {
            return Ok(None);
        }

        // We could avoid the database lookup if the requester is the user we're looking
        // for but that would make the code more complex and we're not very
        // concerned about performance yet
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let user = repo.user().lookup(id).await?;
        repo.cancel().await?;

        Ok(user.map(User))
    }

    /// Check whether a username is available for registration.
    ///
    /// This query is accessible to anonymous users, as it is used during
    /// the registration flow. It intentionally acts as an availability
    /// oracle for registration, unlike `userByUsername` below which hides
    /// user existence, so it is rate-limited per requester.
    async fn username_available(
        &self,
        ctx: &Context<'_>,
        username: String,
    ) -> Result<UsernameAvailability, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();

        if !state.site_config().password_registration_enabled {
            return Err(async_graphql::Error::new(
                "Password registration is disabled on this server",
            ));
        }

        if let Err(e) = state
            .limiter()
            .check_username_availability(requester.fingerprint())
        {
            tracing::warn!(error = &e as &dyn std::error::Error);
            return Err(async_graphql::Error::new("Too many requests"));
        }

        // Cap the length early, so that obviously-invalid input doesn't hit the
        // database or the homeserver.
        if username.len() > 255 {
            return Ok(UsernameAvailability {
                username,
                available: false,
                reason: Some(UsernameUnavailableReason::Invalid),
                violation_codes: Some(vec![
                    mas_policy::ViolationVariant::UsernameTooLong
                        .as_str()
                        .to_owned(),
                ]),
            });
        }

        // Check if the username exists in the MAS database
        let mut repo = state.repository().await?;
        let exists = repo.user().exists(&username).await?;
        repo.cancel().await?;

        if exists {
            return Ok(UsernameAvailability {
                username,
                available: false,
                reason: Some(UsernameUnavailableReason::Taken),
                violation_codes: None,
            });
        }

        // Run the same registration policy the register views use, so that this
        // query doesn't report a username as available when registration would
        // actually reject it
        let mut policy = state.policy().await?;
        let res = policy
            .evaluate_register(mas_policy::RegisterInput {
                registration_method: mas_policy::RegistrationMethod::Password,
                username: &username,
                email: None,
                requester: requester.for_policy(),
            })
            .await?;

        let violation_codes: Vec<String> = res
            .violations
            .into_iter()
            .filter(|violation| violation.field.as_deref() == Some("username"))
            .filter_map(|violation| violation.variant.map(|variant| variant.as_str().to_owned()))
            .collect();

        if !violation_codes.is_empty() {
            return Ok(UsernameAvailability {
                username,
                available: false,
                reason: Some(UsernameUnavailableReason::Invalid),
                violation_codes: Some(violation_codes),
            });
        }

        // Check if the username is available on the homeserver
        let homeserver = state.homeserver_connection();
        let homeserver_available = homeserver.is_localpart_available(&username).await?;

        if !homeserver_available {
            return Ok(UsernameAvailability {
                username,
                available: false,
                reason: Some(UsernameUnavailableReason::Reserved),
                violation_codes: None,
            });
        }

        Ok(UsernameAvailability {
            username,
            available: true,
            reason: None,
            violation_codes: None,
        })
    }

    /// Fetch a user by its username.
    async fn user_by_username(
        &self,
        ctx: &Context<'_>,
        username: String,
    ) -> Result<Option<User>, async_graphql::Error> {
        let requester = ctx.requester();
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user = repo.user().find_by_username(&username).await?;
        let Some(user) = user else {
            // We don't want to leak the existence of a user
            return Ok(None);
        };

        // Users can only see themselves, except for admins
        if !requester.is_owner_or_admin(&user) {
            return Ok(None);
        }

        Ok(Some(User(user)))
    }

    /// Get a list of users.
    ///
    /// This is only available to administrators.
    async fn users(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only users with the given state.")]
        state_param: Option<UserState>,

        #[graphql(
            name = "canRequestAdmin",
            desc = "List only users with the given 'canRequestAdmin' value"
        )]
        can_request_admin_param: Option<bool>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, User, PreloadedTotalCount>, async_graphql::Error> {
        let requester = ctx.requester();
        if !requester.is_admin() {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            async |after, before, first, last| {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::User))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::User))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                // Build the query filter
                let filter = UserFilter::new();
                let filter = match can_request_admin_param {
                    Some(true) => filter.can_request_admin_only(),
                    Some(false) => filter.cannot_request_admin_only(),
                    None => filter,
                };
                let filter = match state_param {
                    Some(UserState::Active) => filter.active_only(),
                    Some(UserState::Locked) => filter.locked_only(),
                    None => filter,
                };

                let page = repo.user().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.user().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|edge| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::User, edge.cursor)),
                        User(edge.node),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}

/// The state of a user.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum UserState {
    /// The user is active.
    Active,

    /// The user is locked.
    Locked,
}
