// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

mod acceptor;
mod maybe;
mod v1;

pub use self::{
    acceptor::{ProxyAcceptError, ProxyAcceptor},
    maybe::MaybeProxyAcceptor,
    v1::ProxyProtocolV1Info,
};
