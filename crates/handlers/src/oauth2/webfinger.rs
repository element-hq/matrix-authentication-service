// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    Json,
    extract::{Query, State},
    response::IntoResponse,
};
use axum_extra::typed_header::TypedHeader;
use headers::ContentType;
use mas_router::UrlBuilder;
use oauth2_types::webfinger::WebFingerResponse;
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct Params {
    resource: String,

    // TODO: handle multiple rel=
    #[serde(default)]
    rel: Option<String>,
}

fn jrd() -> mime::Mime {
    "application/jrd+json".parse().unwrap()
}

#[tracing::instrument(name = "handlers.oauth2.webfinger.get", skip_all)]
pub(crate) async fn get(
    Query(params): Query<Params>,
    State(url_builder): State<UrlBuilder>,
) -> impl IntoResponse {
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
