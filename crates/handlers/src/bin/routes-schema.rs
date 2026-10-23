// Copyright 2026 Element Creations Ltd.
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

//! Generates the API documentation of the paths and methods served by each
//! listener resource, other than the admin API

use std::io::Write;

use aide::{
    axum::ApiRouter,
    openapi::{
        OpenApi, Operation, Parameter, ParameterData, ParameterSchemaOrContent, PathItem,
        PathStyle, ReferenceOr, SchemaObject, Server, ServerVariable,
    },
};
use camino::Utf8PathBuf;
use indexmap::IndexMap;
use mas_router::{Route, UrlBuilder};
use mas_templates::{SiteBranding, SiteFeatures, Templates};

use self::dummy_state::DummyState;

mod dummy_state;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");

    // The human-facing routers need templates to render their errors
    let templates = Templates::load(
        workspace_root.join("templates"),
        UrlBuilder::new("https://example.com/".parse()?, None, None),
        None,
        workspace_root.join("translations"),
        SiteBranding::new("example.com"),
        SiteFeatures {
            password_registration: true,
            password_registration_email_required: true,
            password_login: true,
            account_recovery: true,
            login_with_email_allowed: true,
            minimum_password_complexity: 3,
        },
        false,
    )
    .await?;

    let resources = [
        ("health", mas_handlers::healthcheck_router::<DummyState>()),
        ("discovery", mas_handlers::discovery_router()),
        ("human", mas_handlers::human_router(templates.clone())),
        ("graphql", mas_handlers::graphql_router(false)),
        ("oauth", mas_handlers::api_router()),
        ("compat", mas_handlers::compat_router(templates)),
    ];

    // Tag each operation with the `name` of its resource in the configuration
    let mut router = ApiRouter::new();
    for (name, resource) in resources {
        router = router.merge(resource.with_path_items(|item| item.tag(name)));
    }

    let mut api = OpenApi::default();
    let _ = router.finish_api_with(&mut api, |t| {
        t.title("Matrix Authentication Service").description(
            "Paths and methods served by each listener resource, tagged with the resource's \
             `name` in the configuration. Request and response bodies are not documented. \
             The admin API is described in `spec.json`.",
        )
    });

    let paths = api.paths.get_or_insert_default();

    // Those are mounted by mas-cli
    for (name, path) in [
        ("prometheus", "/metrics".to_owned()),
        (
            "assets",
            format!("{}{{*path}}", mas_router::StaticAsset::route()),
        ),
        ("connection-info", "/connection-info".to_owned()),
    ] {
        let operation = Operation {
            tags: vec![name.to_owned()],
            ..Operation::default()
        };
        let item = PathItem {
            get: Some(operation),
            ..PathItem::default()
        };
        paths.paths.insert(path, ReferenceOr::Item(item));
    }

    paths.paths = std::mem::take(&mut paths.paths)
        .into_iter()
        .map(|(path, mut item)| {
            if let ReferenceOr::Item(item) = &mut item {
                item.parameters = path_parameters(&path);
            }
            // OpenAPI has no syntax for axum's `{*rest}` wildcards
            (path.replace("{*", "{"), item)
        })
        .collect();

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

/// The parameters of an axum path, e.g. `id` in `/users/{id}`
fn path_parameters(path: &str) -> Vec<ReferenceOr<Parameter>> {
    path.split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| {
            let description = name
                .starts_with('*')
                .then(|| "Any number of path segments".to_owned());
            ReferenceOr::Item(Parameter::Path {
                parameter_data: ParameterData {
                    name: name.trim_start_matches('*').to_owned(),
                    description,
                    required: true,
                    deprecated: None,
                    format: ParameterSchemaOrContent::Schema(SchemaObject {
                        json_schema: schemars::json_schema!({ "type": "string" }),
                        external_docs: None,
                        example: None,
                    }),
                    example: None,
                    examples: IndexMap::new(),
                    explode: None,
                    extensions: IndexMap::new(),
                },
                style: PathStyle::Simple,
            })
        })
        .collect()
}
