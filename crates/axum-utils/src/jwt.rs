// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::response::{IntoResponse, Response};
use axum_extra::typed_header::TypedHeader;
use headers::ContentType;
use mas_jose::jwt::Jwt;
use mime::Mime;

pub struct JwtResponse<T>(pub Jwt<'static, T>);

impl<T> IntoResponse for JwtResponse<T> {
    fn into_response(self) -> Response {
        let application_jwt: Mime = "application/jwt".parse().unwrap();
        let content_type = ContentType::from(application_jwt);
        (TypedHeader(content_type), self.0.into_string()).into_response()
    }
}
