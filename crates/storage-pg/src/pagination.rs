// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Utilities to manage paginated queries.

use mas_storage::{
    Pagination,
    pagination::{Ordering, PaginationDirection},
};
use sea_query::{ColumnRef, Expr, IntoColumnRef, SimpleExpr};
use ulid::Ulid;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UlidColumn {
    column: ColumnRef,
}

impl Ordering for UlidColumn {
    type Cursor = Ulid;
}

pub trait PaginationExt {
    fn for_ulid_column(self, column: impl IntoColumnRef) -> Pagination<UlidColumn>;
}

impl PaginationExt for Pagination {
    fn for_ulid_column(self, column: impl IntoColumnRef) -> Pagination<UlidColumn> {
        Pagination {
            before: self.before,
            after: self.after,
            count: self.count,
            direction: self.direction,
            ordering: UlidColumn {
                column: column.into_column_ref(),
            },
        }
    }
}

/// Trait to help building paginated queries based on the ordering criteria and
/// the cursors
pub trait SqlOrdering: Ordering {
    /// Get the list of columns used during the ordering and for comparison with
    /// the cursor
    fn columns(&self) -> Vec<SimpleExpr>;

    /// Get the list of values in a cursor
    fn values(&self, cursor: Self::Cursor) -> Vec<SimpleExpr>;
}

impl SqlOrdering for UlidColumn {
    fn columns(&self) -> Vec<SimpleExpr> {
        vec![self.column.clone().into()]
    }

    fn values(&self, cursor: Ulid) -> Vec<SimpleExpr> {
        vec![Uuid::from(cursor).into()]
    }
}

/// An extension trait to the [`sqlx::QueryBuilder`], to help adding pagination
/// to a query
pub trait QueryBuilderExt {
    /// Add cursor-based pagination to a query, as used in paginated GraphQL
    /// connections
    fn generate_pagination<O: SqlOrdering>(&mut self, pagination: Pagination<O>) -> &mut Self;
}

impl QueryBuilderExt for sea_query::SelectStatement {
    fn generate_pagination<O: SqlOrdering>(&mut self, pagination: Pagination<O>) -> &mut Self {
        let columns = pagination.ordering.columns();

        // ref: https://github.com/graphql/graphql-relay-js/issues/94#issuecomment-232410564
        // 1. Start from the greedy query: SELECT * FROM table

        // 2. If the after argument is provided, add `id > parsed_cursor` to the `WHERE`
        // clause
        if let Some(after) = pagination.after {
            let columns = Expr::tuple(columns.iter().cloned());
            let after = Expr::tuple(pagination.ordering.values(after));
            self.and_where(columns.gt(after));
        }

        // 3. If the before argument is provided, add `id < parsed_cursor` to the
        // `WHERE` clause
        if let Some(before) = pagination.before {
            let columns = Expr::tuple(columns.iter().cloned());
            let before = Expr::tuple(pagination.ordering.values(before));
            self.and_where(columns.lt(before));
        }

        match pagination.direction {
            // 4. If the first argument is provided, add `ORDER BY id ASC LIMIT first+1` to the
            // query
            PaginationDirection::Forward => {
                for column in columns {
                    self.order_by_expr(column, sea_query::Order::Asc);
                }
            }
            // 5. If the last argument is provided, add `ORDER BY id DESC LIMIT last+1` to the
            // query
            PaginationDirection::Backward => {
                for column in columns {
                    self.order_by_expr(column, sea_query::Order::Desc);
                }
            }
        }

        self.limit((pagination.count + 1) as u64);

        self
    }
}
