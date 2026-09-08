// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

mod link;
mod link_token;
mod provider;
mod session;

pub use self::{
    link::UpstreamOAuthLink,
    link_token::UpstreamOAuthLinkToken,
    provider::{
        ClaimsImports as UpstreamOAuthProviderClaimsImports,
        DiscoveryMode as UpstreamOAuthProviderDiscoveryMode,
        ImportAction as UpstreamOAuthProviderImportAction,
        ImportPreference as UpstreamOAuthProviderImportPreference,
        LocalpartPreference as UpstreamOAuthProviderLocalpartPreference,
        OnBackchannelLogout as UpstreamOAuthProviderOnBackchannelLogout,
        OnConflict as UpstreamOAuthProviderOnConflict, PkceMode as UpstreamOAuthProviderPkceMode,
        ResponseMode as UpstreamOAuthProviderResponseMode,
        SubjectPreference as UpstreamOAuthProviderSubjectPreference,
        TokenAuthMethod as UpstreamOAuthProviderTokenAuthMethod, UpstreamOAuthProvider,
    },
    session::{UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState},
};
