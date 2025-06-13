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
pub struct Pagination {
    /// The cursor to start from
    pub before: Option<Ulid>,

    /// The cursor to end at
    pub after: Option<Ulid>,

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

impl Pagination {
    /// Creates a new [`Pagination`] from user-provided parameters.
    ///
    /// # Errors
    ///
    /// Either `first` or `last` must be provided, else this function will
    /// return an [`InvalidPagination`] error.
    pub const fn try_new(
        before: Option<Ulid>,
        after: Option<Ulid>,
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
    pub const fn before(mut self, id: Ulid) -> Self {
        self.before = Some(id);
        self
    }

    /// Clear the before cursor
    #[must_use]
    pub const fn clear_before(mut self) -> Self {
        self.before = None;
        self
    }

    /// Get items after the given cursor
    #[must_use]
    pub const fn after(mut self, id: Ulid) -> Self {
        self.after = Some(id);
        self
    }

    /// Clear the after cursor
    #[must_use]
    pub const fn clear_after(mut self) -> Self {
        self.after = None;
        self
    }

    /// Process a page returned by a paginated query
    #[must_use]
    pub fn process<T>(&self, mut edges: Vec<T>) -> Page<T> {
        let is_full = edges.len() == (self.count + 1);
        if is_full {
            edges.pop();
        }

        let (has_previous_page, has_next_page) = match self.direction {
            PaginationDirection::Forward => (false, is_full),
            PaginationDirection::Backward => {
                // 6. If the last argument is provided, I reverse the order of the results
                edges.reverse();
                (is_full, false)
            }
        };

        Page {
            has_next_page,
            has_previous_page,
            edges,
        }
    }
}

/// A page of results returned by a paginated query
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// When paginating forwards, this is true if there are more items after
    pub has_next_page: bool,

    /// When paginating backwards, this is true if there are more items before
    pub has_previous_page: bool,

    /// The items in the page
    pub edges: Vec<T>,
}

impl<T> Page<T> {
    /// Map the items in this page with the given function
    ///
    /// # Parameters
    ///
    /// * `f`: The function to map the items with
    #[must_use]
    pub fn map<F, T2>(self, f: F) -> Page<T2>
    where
        F: FnMut(T) -> T2,
    {
        let edges = self.edges.into_iter().map(f).collect();
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
    pub fn try_map<F, E, T2>(self, f: F) -> Result<Page<T2>, E>
    where
        F: FnMut(T) -> Result<T2, E>,
    {
        let edges: Result<Vec<T2>, E> = self.edges.into_iter().map(f).collect();
        Ok(Page {
            has_next_page: self.has_next_page,
            has_previous_page: self.has_previous_page,
            edges: edges?,
        })
    }
}
