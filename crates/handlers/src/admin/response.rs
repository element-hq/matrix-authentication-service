// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(clippy::module_name_repetitions)]

use mas_storage::Pagination;
use schemars::JsonSchema;
use serde::Serialize;
use ulid::Ulid;

use super::model::Resource;

/// Related links
#[derive(Serialize, JsonSchema)]
struct PaginationLinks {
    /// The canonical link to the current page
    #[serde(rename = "self")]
    self_: String,

    /// The link to the first page of results
    first: String,

    /// The link to the last page of results
    last: String,

    /// The link to the next page of results
    ///
    /// Only present if there is a next page
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,

    /// The link to the previous page of results
    ///
    /// Only present if there is a previous page
    #[serde(skip_serializing_if = "Option::is_none")]
    prev: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct PaginationMeta {
    /// The total number of results
    count: usize,
}

/// A top-level response with a page of resources
#[derive(Serialize, JsonSchema)]
pub struct PaginatedResponse<T> {
    /// Response metadata
    meta: PaginationMeta,

    /// The list of resources
    data: Vec<SingleResource<T>>,

    /// Related links
    links: PaginationLinks,
}

fn url_with_pagination(base: &str, pagination: Pagination) -> String {
    let (path, query) = base.split_once('?').unwrap_or((base, ""));
    let mut query = query.to_owned();

    if let Some(before) = pagination.before {
        query = format!("{query}&page[before]={before}");
    }

    if let Some(after) = pagination.after {
        query = format!("{query}&page[after]={after}");
    }

    let count = pagination.count;
    match pagination.direction {
        mas_storage::pagination::PaginationDirection::Forward => {
            query = format!("{query}&page[first]={count}");
        }
        mas_storage::pagination::PaginationDirection::Backward => {
            query = format!("{query}&page[last]={count}");
        }
    }

    // Remove the first '&'
    let query = query.trim_start_matches('&');

    format!("{path}?{query}")
}

impl<T: Resource> PaginatedResponse<T> {
    pub fn new(
        page: mas_storage::Page<T>,
        current_pagination: Pagination,
        count: usize,
        base: &str,
    ) -> Self {
        let links = PaginationLinks {
            self_: url_with_pagination(base, current_pagination),
            first: url_with_pagination(base, Pagination::first(current_pagination.count)),
            last: url_with_pagination(base, Pagination::last(current_pagination.count)),
            next: page.has_next_page.then(|| {
                url_with_pagination(
                    base,
                    current_pagination
                        .clear_before()
                        .after(page.edges.last().unwrap().id()),
                )
            }),
            prev: if page.has_previous_page {
                Some(url_with_pagination(
                    base,
                    current_pagination
                        .clear_after()
                        .before(page.edges.first().unwrap().id()),
                ))
            } else {
                None
            },
        };

        let data = page.edges.into_iter().map(SingleResource::new).collect();

        Self {
            meta: PaginationMeta { count },
            data,
            links,
        }
    }
}

/// A single resource, with its type, ID, attributes and related links
#[derive(Serialize, JsonSchema)]
struct SingleResource<T> {
    /// The type of the resource
    #[serde(rename = "type")]
    type_: &'static str,

    /// The ID of the resource
    #[schemars(with = "super::schema::Ulid")]
    id: Ulid,

    /// The attributes of the resource
    attributes: T,

    /// Related links
    links: SelfLinks,
}

impl<T: Resource> SingleResource<T> {
    fn new(resource: T) -> Self {
        let self_ = resource.path();
        Self {
            type_: T::KIND,
            id: resource.id(),
            attributes: resource,
            links: SelfLinks { self_ },
        }
    }
}

/// Related links
#[derive(Serialize, JsonSchema)]
struct SelfLinks {
    /// The canonical link to the current resource
    #[serde(rename = "self")]
    self_: String,
}

/// A top-level response with a single resource
#[derive(Serialize, JsonSchema)]
pub struct SingleResponse<T> {
    data: SingleResource<T>,
    links: SelfLinks,
}

impl<T: Resource> SingleResponse<T> {
    /// Create a new single response with the given resource and link to itself
    pub fn new(resource: T, self_: String) -> Self {
        Self {
            data: SingleResource::new(resource),
            links: SelfLinks { self_ },
        }
    }

    /// Create a new single response using the canonical path for the resource
    pub fn new_canonical(resource: T) -> Self {
        let self_ = resource.path();
        Self::new(resource, self_)
    }
}

/// A single error
#[derive(Serialize, JsonSchema)]
struct Error {
    /// A human-readable title for the error
    title: String,
}

impl Error {
    fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        Self {
            title: error.to_string(),
        }
    }
}

/// A top-level response with a list of errors
#[derive(Serialize, JsonSchema)]
pub struct ErrorResponse {
    /// The list of errors
    errors: Vec<Error>,
}

impl ErrorResponse {
    /// Create a new error response from any Rust error
    pub fn from_error(error: &(dyn std::error::Error + 'static)) -> Self {
        let mut errors = Vec::new();
        let mut head = Some(error);
        while let Some(error) = head {
            errors.push(Error::from_error(error));
            head = error.source();
        }
        Self { errors }
    }
}
