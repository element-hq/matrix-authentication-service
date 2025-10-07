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

/// An error returned when invalid cursor is provided
#[derive(Debug, Error)]
#[error("Invalid cursor")]
pub struct InvalidCursor;

/// Defines a pagination ordering criteria
pub trait Ordering: Clone {
    /// The type of cursor for this criteria
    type Cursor: Clone;

    /// Returns the corresponding ordering parameter, if set
    fn as_parameter(&self) -> Option<&'static str>;

    /// Parse a cursor from a string
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCursor`] if the cursor is invalid
    fn parse_cursor(&self, cursor: &str) -> Result<Self::Cursor, InvalidCursor>;

    /// Serialize a cursor to a string
    fn serialize_cursor(&self, cursor: &Self::Cursor) -> String;
}

impl Ordering for () {
    // The default ordering orders by the object primary key, which is a ULID
    type Cursor = Ulid;

    fn as_parameter(&self) -> Option<&'static str> {
        None
    }

    fn parse_cursor(&self, cursor: &str) -> Result<Self::Cursor, InvalidCursor> {
        cursor.parse().map_err(|_| InvalidCursor)
    }

    fn serialize_cursor(&self, cursor: &Self::Cursor) -> String {
        cursor.to_string()
    }
}

/// Pagination parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pagination<O: Ordering = ()> {
    /// The cursor to start from
    pub before: Option<O::Cursor>,

    /// The cursor to end at
    pub after: Option<O::Cursor>,

    /// The maximum number of items to return
    pub count: usize,

    /// The criteria to order the results by
    pub ordering: O,

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
pub trait Node {
    /// The ordering type associated with this node type
    type Ordering: Ordering;

    /// The cursor of that particular node
    fn cursor(&self, ordering: &Self::Ordering) -> <Self::Ordering as Ordering>::Cursor;
}

impl<O: Ordering> Pagination<O> {
    /// Creates a new [`Pagination`] from user-provided parameters.
    ///
    /// # Errors
    ///
    /// Either `first` or `last` must be provided, else this function will
    /// return an [`InvalidPagination`] error.
    pub fn try_new(
        before: Option<O::Cursor>,
        after: Option<O::Cursor>,
        first: Option<usize>,
        last: Option<usize>,
    ) -> Result<Self, InvalidPagination>
    where
        O: Default,
    {
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
            ordering: O::default(),
        })
    }

    /// Creates a [`Pagination`] which gets the first N items with the given
    /// ordering
    #[must_use]
    pub fn first_with_ordering(first: usize, ordering: O) -> Self {
        Self {
            before: None,
            after: None,
            count: first,
            direction: PaginationDirection::Forward,
            ordering,
        }
    }

    /// Creates a [`Pagination`] which gets the first N items
    #[must_use]
    pub fn first(first: usize) -> Self
    where
        O: Default,
    {
        Self::first_with_ordering(first, O::default())
    }

    /// Creates a [`Pagination`] which gets the last N items with the given
    /// ordering
    #[must_use]
    pub fn last_with_ordering(last: usize, ordering: O) -> Self {
        Self {
            before: None,
            after: None,
            count: last,
            direction: PaginationDirection::Backward,
            ordering,
        }
    }

    /// Creates a [`Pagination`] which gets the last N items
    #[must_use]
    pub fn last(last: usize) -> Self
    where
        O: Default,
    {
        Self::last_with_ordering(last, O::default())
    }

    /// Get items before the given cursor
    #[must_use]
    pub fn before(mut self, cursor: O::Cursor) -> Self {
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
    pub fn after(mut self, cursor: O::Cursor) -> Self {
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
    pub fn process<T: Node<Ordering = O>>(&self, mut nodes: Vec<T>) -> Page<T, O::Cursor> {
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
                cursor: node.cursor(&self.ordering),
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
