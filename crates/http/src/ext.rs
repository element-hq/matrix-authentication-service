// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::OnceLock;

use http::header::HeaderName;
use tower_http::cors::CorsLayer;

static PROPAGATOR_HEADERS: OnceLock<Vec<HeaderName>> = OnceLock::new();

/// Notify the CORS layer what opentelemetry propagators are being used. This
/// helps whitelisting headers in CORS requests.
///
/// # Panics
///
/// When called twice
pub fn set_propagator(propagator: &dyn opentelemetry::propagation::TextMapPropagator) {
    let headers = propagator
        .fields()
        .map(|h| HeaderName::try_from(h).unwrap())
        .collect();

    tracing::debug!(
        ?headers,
        "Headers allowed in CORS requests for trace propagators set"
    );
    PROPAGATOR_HEADERS
        .set(headers)
        .expect(concat!(module_path!(), "::set_propagator was called twice"));
}

pub trait CorsLayerExt {
    #[must_use]
    fn allow_otel_headers<H>(self, headers: H) -> Self
    where
        H: IntoIterator<Item = HeaderName>;
}

impl CorsLayerExt for CorsLayer {
    fn allow_otel_headers<H>(self, headers: H) -> Self
    where
        H: IntoIterator<Item = HeaderName>,
    {
        let base = PROPAGATOR_HEADERS.get().cloned().unwrap_or_default();
        let headers: Vec<_> = headers.into_iter().chain(base).collect();
        self.allow_headers(headers)
    }
}
