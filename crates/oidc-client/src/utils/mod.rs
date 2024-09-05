// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::ops::RangeBounds;

use bytes::Buf;
use http::{Response, StatusCode};

use crate::error::ErrorBody;

pub fn http_error_mapper<T>(response: Response<T>) -> Option<ErrorBody>
where
    T: Buf,
{
    let body = response.into_body();
    serde_json::from_reader(body.reader()).ok()
}

pub fn http_all_error_status_codes() -> impl RangeBounds<StatusCode> {
    let Ok(client_errors_start_code) = StatusCode::from_u16(400) else {
        unreachable!()
    };
    let Ok(server_errors_end_code) = StatusCode::from_u16(599) else {
        unreachable!()
    };

    client_errors_start_code..=server_errors_end_code
}
