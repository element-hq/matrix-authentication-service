// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Utilities to manage paginated queries.

use mas_storage::{Pagination, pagination::PaginationDirection};
use sea_query::IntoColumnRef;
use uuid::Uuid;

/// An extension trait to the `sqlx` [`QueryBuilder`], to help adding pagination
/// to a query
pub trait QueryBuilderExt {
    /// Add cursor-based pagination to a query, as used in paginated GraphQL
    /// connections
    fn generate_pagination<C: IntoColumnRef>(
        &mut self,
        column: C,
        pagination: Pagination,
    ) -> &mut Self;
}

impl QueryBuilderExt for sea_query::SelectStatement {
    fn generate_pagination<C: IntoColumnRef>(
        &mut self,
        column: C,
        pagination: Pagination,
    ) -> &mut Self {
        let id_field = column.into_column_ref();

        // ref: https://github.com/graphql/graphql-relay-js/issues/94#issuecomment-232410564
        // 1. Start from the greedy query: SELECT * FROM table

        // 2. If the after argument is provided, add `id > parsed_cursor` to the `WHERE`
        // clause
        if let Some(after) = pagination.after {
            self.and_where(sea_query::Expr::col(id_field.clone()).gt(Uuid::from(after)));
        }

        // 3. If the before argument is provided, add `id < parsed_cursor` to the
        // `WHERE` clause
        if let Some(before) = pagination.before {
            self.and_where(sea_query::Expr::col(id_field.clone()).lt(Uuid::from(before)));
        }

        match pagination.direction {
            // 4. If the first argument is provided, add `ORDER BY id ASC LIMIT first+1` to the
            // query
            PaginationDirection::Forward => {
                self.order_by(id_field, sea_query::Order::Asc)
                    .limit((pagination.count + 1) as u64);
            }
            // 5. If the first argument is provided, add `ORDER BY id DESC LIMIT last+1` to the
            // query
            PaginationDirection::Backward => {
                self.order_by(id_field, sea_query::Order::Desc)
                    .limit((pagination.count + 1) as u64);
            }
        }

        self
    }
}
