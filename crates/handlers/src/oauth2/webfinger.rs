// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::transform::TransformOperation;
use axum::{Json, extract::State};
use axum_extra::{extract::Query, typed_header::TypedHeader};
use headers::ContentType;
use mas_router::UrlBuilder;
use oauth2_types::webfinger::WebFingerResponse;
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
pub(crate) struct Params {
    /// The URI of the entity to describe
    resource: String,

    /// The relation type of the links to return. Only
    /// `http://openid.net/specs/connect/1.0/issuer` is supported, and no links
    /// are returned without it.
    // TODO: handle multiple rel=
    rel: Option<String>,
}

fn jrd() -> mime::Mime {
    "application/jrd+json".parse().unwrap()
}

pub(crate) fn doc(operation: TransformOperation) -> TransformOperation {
    operation
        .summary("Discover the OpenID Connect issuer of an entity")
        .response_with::<200, Json<WebFingerResponse>, _>(|mut t| {
            let response = t.inner();
            response.content = std::mem::take(&mut response.content)
                .into_values()
                .map(|media| (jrd().to_string(), media))
                .collect();
            t
        })
}

#[tracing::instrument(name = "handlers.oauth2.webfinger.get", skip_all)]
pub(crate) async fn get(
    Query(params): Query<Params>,
    State(url_builder): State<UrlBuilder>,
) -> (TypedHeader<ContentType>, Json<WebFingerResponse>) {
    // TODO: should we validate the subject?
    let subject = params.resource;

    let wants_issuer = params
        .rel
        .iter()
        .any(|i| i == "http://openid.net/specs/connect/1.0/issuer");

    let res = if wants_issuer {
        WebFingerResponse::new(subject).with_issuer(url_builder.oidc_issuer())
    } else {
        WebFingerResponse::new(subject)
    };

    (TypedHeader(ContentType::from(jrd())), Json(res))
}
