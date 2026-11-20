// Copyright 2025, 2026 Element Creations Ltd.
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

use std::io::Write;

use aide::openapi::{Server, ServerVariable};
use indexmap::IndexMap;

use self::dummy_state::DummyState;

mod dummy_state;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut api, _) = mas_handlers::admin_api_router::<DummyState>();

    // Set the server list to a configurable base URL
    api.servers = vec![Server {
        url: "{base}".to_owned(),
        variables: IndexMap::from([(
            "base".to_owned(),
            ServerVariable {
                default: "/".to_owned(),
                description: Some("The base URL of the listener".to_owned()),
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
