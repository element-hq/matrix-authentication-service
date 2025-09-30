// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Utilities to manage paginated queries.

use thiserror::Error;
use ulid::Ulid;

/// An error returned when invalid pagination parameters are provided
#[derive(Debug, Error)]
#[error("Either 'first' or 'last' must be specified")]
pub struct InvalidPagination;

/// Pagination parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination<Cursor = Ulid> {
    /// The cursor to start from
    pub before: Option<Cursor>,

    /// The cursor to end at
    pub after: Option<Cursor>,

    /// The maximum number of items to return
    pub count: usize,

    /// In which direction to paginate
    pub direction: PaginationDirection,
}

/// The direction to paginate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaginationDirection {
    /// Paginate forward
    Forward,

    /// Paginate backward
    Backward,
}

/// A node in a page, with a cursor
pub trait Node<C = Ulid> {
    /// The cursor of that particular node
    fn cursor(&self) -> C;
}

impl<C> Pagination<C> {
    /// Creates a new [`Pagination`] from user-provided parameters.
    ///
    /// # Errors
    ///
    /// Either `first` or `last` must be provided, else this function will
    /// return an [`InvalidPagination`] error.
    pub fn try_new(
        before: Option<C>,
        after: Option<C>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Self, InvalidPagination> {
        let (direction, count) = match (first, last) {
            (Some(first), _) => (PaginationDirection::Forward, first),
            (_, Some(last)) => (PaginationDirection::Backward, last),
            (None, None) => return Err(InvalidPagination),
        };

        Ok(Self {
            before,
            after,
            count,
            direction,
        })
    }

    /// Creates a [`Pagination`] which gets the first N items
    #[must_use]
    pub const fn first(first: usize) -> Self {
        Self {
            before: None,
            after: None,
            count: first,
            direction: PaginationDirection::Forward,
        }
    }

    /// Creates a [`Pagination`] which gets the last N items
    #[must_use]
    pub const fn last(last: usize) -> Self {
        Self {
            before: None,
            after: None,
            count: last,
            direction: PaginationDirection::Backward,
        }
    }

    /// Get items before the given cursor
    #[must_use]
    pub fn before(mut self, cursor: C) -> Self {
        self.before = Some(cursor);
        self
    }

    /// Clear the before cursor
    #[must_use]
    pub fn clear_before(mut self) -> Self {
        self.before = None;
        self
    }

    /// Get items after the given cursor
    #[must_use]
    pub fn after(mut self, cursor: C) -> Self {
        self.after = Some(cursor);
        self
    }

    /// Clear the after cursor
    #[must_use]
    pub fn clear_after(mut self) -> Self {
        self.after = None;
        self
    }

    /// Process a page returned by a paginated query
    #[must_use]
    pub fn process<T: Node<C>>(&self, mut nodes: Vec<T>) -> Page<T, C> {
        let is_full = nodes.len() == (self.count + 1);
        if is_full {
            nodes.pop();
        }

        let (has_previous_page, has_next_page) = match self.direction {
            PaginationDirection::Forward => (false, is_full),
            PaginationDirection::Backward => {
                // 6. If the last argument is provided, I reverse the order of the results
                nodes.reverse();
                (is_full, false)
            }
        };

        let edges = nodes
            .into_iter()
            .map(|node| Edge {
                cursor: node.cursor(),
                node,
            })
            .collect();

        Page {
            has_next_page,
            has_previous_page,
            edges,
        }
    }
}

/// An edge in a paginated result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge<T, C = Ulid> {
    /// The cursor of the edge
    pub cursor: C,
    /// The node of the edge
    pub node: T,
}

/// A page of results returned by a paginated query
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T, C = Ulid> {
    /// When paginating forwards, this is true if there are more items after
    pub has_next_page: bool,

    /// When paginating backwards, this is true if there are more items before
    pub has_previous_page: bool,

    /// The items in the page
    pub edges: Vec<Edge<T, C>>,
}

impl<T, C> Page<T, C> {
    /// Map the items in this page with the given function
    ///
    /// # Parameters
    ///
    /// * `f`: The function to map the items with
    #[must_use]
    pub fn map<F, T2>(self, mut f: F) -> Page<T2, C>
    where
        F: FnMut(T) -> T2,
    {
        let edges = self
            .edges
            .into_iter()
            .map(|edge| Edge {
                cursor: edge.cursor,
                node: f(edge.node),
            })
            .collect();
        Page {
            has_next_page: self.has_next_page,
            has_previous_page: self.has_previous_page,
            edges,
        }
    }

    /// Try to map the items in this page with the given fallible function
    ///
    /// # Parameters
    ///
    /// * `f`: The fallible function to map the items with
    ///
    /// # Errors
    ///
    /// Returns the first error encountered while mapping the items
    pub fn try_map<F, E, T2>(self, mut f: F) -> Result<Page<T2, C>, E>
    where
        F: FnMut(T) -> Result<T2, E>,
    {
        let edges: Result<Vec<Edge<T2, C>>, E> = self
            .edges
            .into_iter()
            .map(|edge| {
                Ok(Edge {
                    cursor: edge.cursor,
                    node: f(edge.node)?,
                })
            })
            .collect();

        Ok(Page {
            has_next_page: self.has_next_page,
            has_previous_page: self.has_previous_page,
            edges: edges?,
        })
    }
}
