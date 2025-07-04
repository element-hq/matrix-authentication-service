// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

mod link;
mod provider;
mod session;

pub use self::{
    link::UpstreamOAuthLink,
    provider::{
        ClaimsImports as UpstreamOAuthProviderClaimsImports,
        DiscoveryMode as UpstreamOAuthProviderDiscoveryMode,
        ImportAction as UpstreamOAuthProviderImportAction,
        ImportPreference as UpstreamOAuthProviderImportPreference,
        OnBackchannelLogout as UpstreamOAuthProviderOnBackchannelLogout,
        PkceMode as UpstreamOAuthProviderPkceMode,
        ResponseMode as UpstreamOAuthProviderResponseMode,
        SubjectPreference as UpstreamOAuthProviderSubjectPreference,
        TokenAuthMethod as UpstreamOAuthProviderTokenAuthMethod, UpstreamOAuthProvider,
    },
    session::{UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState},
};
