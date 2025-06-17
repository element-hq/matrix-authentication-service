// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use tracing::Span;

use super::enrich_span::EnrichSpan;
use crate::utils::FnWrapper;

/// A trait for creating a span for a request.
pub trait MakeSpan<R> {
    fn make_span(&self, request: &R) -> Span;
}

impl<R, F> MakeSpan<R> for FnWrapper<F>
where
    F: Fn(&R) -> Span,
{
    fn make_span(&self, request: &R) -> Span {
        (self.0)(request)
    }
}

/// Make span from a function.
pub fn make_span_fn<R, F>(f: F) -> FnWrapper<F>
where
    F: Fn(&R) -> Span,
{
    FnWrapper(f)
}

/// A macro to implement [`MakeSpan`] for a tuple of types, where the first type
/// implements [`MakeSpan`] and the rest implement [`EnrichSpan`].
macro_rules! impl_for_tuple {
    (M, $($T:ident),+) => {
        impl<R, M, $($T),+> MakeSpan<R> for (M, $($T),+)
        where
            M: MakeSpan<R>,
            $($T: EnrichSpan<R>),+
        {
            fn make_span(&self, request: &R) -> Span {
                #[allow(non_snake_case)]
                let (ref m, $(ref $T),+) = *self;

                let span = m.make_span(request);
                $(
                    $T.enrich_span(&span, request);
                )+
                span
            }
        }
    };
}

impl_for_tuple!(M, T1);
impl_for_tuple!(M, T1, T2);
impl_for_tuple!(M, T1, T2, T3);
impl_for_tuple!(M, T1, T2, T3, T4);
impl_for_tuple!(M, T1, T2, T3, T4, T5);
impl_for_tuple!(M, T1, T2, T3, T4, T5, T6);
impl_for_tuple!(M, T1, T2, T3, T4, T5, T6, T7);
impl_for_tuple!(M, T1, T2, T3, T4, T5, T6, T7, T8);
