// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::borrow::Cow;

use tower_layer::Layer;
use tower_service::Service;

use crate::LogContextService;

/// A layer which creates a log context for each request.
pub struct LogContextLayer<R> {
    tagger: fn(&R) -> Cow<'static, str>,
}

impl<R> Clone for LogContextLayer<R> {
    fn clone(&self) -> Self {
        Self {
            tagger: self.tagger,
        }
    }
}

impl<R> LogContextLayer<R> {
    pub fn new(tagger: fn(&R) -> Cow<'static, str>) -> Self {
        Self { tagger }
    }
}

impl<S, R> Layer<S> for LogContextLayer<R>
where
    S: Service<R>,
{
    type Service = LogContextService<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        LogContextService::new(inner, self.tagger)
    }
}
