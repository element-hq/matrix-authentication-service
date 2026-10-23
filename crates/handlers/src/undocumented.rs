// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use aide::{NoApi, operation::OperationHandler};
use axum::{extract::Request, handler::Handler};

/// A handler whose inputs and outputs are not described in the API documentation
#[derive(Clone)]
pub(crate) struct Undocumented<H>(pub H);

impl<H, T, S> Handler<T, S> for Undocumented<H>
where
    H: Handler<T, S>,
{
    type Future = H::Future;

    fn call(self, req: Request, state: S) -> Self::Future {
        self.0.call(req, state)
    }
}

impl<H> OperationHandler<(), NoApi<()>> for Undocumented<H> {}
