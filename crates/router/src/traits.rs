// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::borrow::Cow;

use serde::Serialize;
use url::Url;

pub trait Route {
    type Query: Serialize;
    fn route() -> &'static str;
    fn query(&self) -> Option<&Self::Query> {
        None
    }

    fn path(&self) -> Cow<'static, str> {
        Cow::Borrowed(Self::route())
    }

    fn path_and_query(&self) -> Cow<'static, str> {
        let path = self.path();
        if let Some(query) = self.query() {
            let query = serde_urlencoded::to_string(query).unwrap();

            if query.is_empty() {
                path
            } else {
                format!("{path}?{query}").into()
            }
        } else {
            path
        }
    }

    fn absolute_url(&self, base: &Url) -> Url {
        let relative = self.path_and_query();
        let relative = relative.trim_start_matches('/');
        base.join(relative).unwrap()
    }
}

pub trait SimpleRoute {
    const PATH: &'static str;
}

impl<T: SimpleRoute> Route for T {
    type Query = ();
    fn route() -> &'static str {
        Self::PATH
    }
}
