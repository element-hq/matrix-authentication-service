// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::{
    Context, Enum, ID, Object,
    connection::{Connection, Edge, OpaqueCursor, query},
};
use mas_storage::{Pagination, user::UserFilter};

use crate::graphql::{
    UserId,
    model::{Cursor, NodeCursor, NodeType, PreloadedTotalCount, User},
    state::ContextExt as _,
};

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
                connection.edges.extend(
                    page.edges.into_iter().map(|p| {
                        Edge::new(OpaqueCursor(NodeCursor(NodeType::User, p.id)), User(p))
                    }),
                );

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
