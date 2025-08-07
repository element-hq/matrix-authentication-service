// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::str_to_string,
    rustdoc::broken_intra_doc_links,
    clippy::future_not_send
)]
#![warn(clippy::pedantic)]

use std::{io::Write, sync::Arc};

use aide::openapi::{Server, ServerVariable};
use indexmap::IndexMap;

/// This is a dummy state, it should never be used.
///
/// We use it to generate the API schema, which doesn't execute any request.
#[derive(Clone)]
struct DummyState;

macro_rules! impl_from_request_parts {
    ($type:ty) => {
        impl axum::extract::FromRequestParts<DummyState> for $type {
            type Rejection = std::convert::Infallible;

            async fn from_request_parts(
                _parts: &mut axum::http::request::Parts,
                _state: &DummyState,
            ) -> Result<Self, Self::Rejection> {
                unimplemented!("This is a dummy state, it should never be used")
            }
        }
    };
}

macro_rules! impl_from_ref {
    ($type:ty) => {
        impl axum::extract::FromRef<DummyState> for $type {
            fn from_ref(_input: &DummyState) -> Self {
                unimplemented!("This is a dummy state, it should never be used")
            }
        }
    };
}

impl_from_request_parts!(mas_storage::BoxRepository);
impl_from_request_parts!(mas_data_model::BoxClock);
impl_from_request_parts!(mas_data_model::BoxRng);
impl_from_request_parts!(mas_handlers::BoundActivityTracker);
impl_from_ref!(mas_router::UrlBuilder);
impl_from_ref!(mas_templates::Templates);
impl_from_ref!(Arc<dyn mas_matrix::HomeserverConnection>);
impl_from_ref!(mas_keystore::Keystore);
impl_from_ref!(mas_handlers::passwords::PasswordManager);
impl_from_ref!(Arc<mas_policy::PolicyFactory>);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut api, _) = mas_handlers::admin_api_router::<DummyState>();

    // Set the server list to a configurable base URL
    api.servers = vec![Server {
        url: "{base}".to_owned(),
        variables: IndexMap::from([(
            "base".to_owned(),
            ServerVariable {
                default: "/".to_owned(),
                ..ServerVariable::default()
            },
        )]),
        ..Server::default()
    }];

    let mut stdout = std::io::stdout();
    serde_json::to_writer_pretty(&mut stdout, &api)?;

    // Make sure we end with a newline
    stdout.write_all(b"\n")?;

    Ok(())
}
