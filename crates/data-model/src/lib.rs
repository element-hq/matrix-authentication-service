// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

pub(crate) mod compat;
pub mod oauth2;
mod site_config;
pub(crate) mod tokens;
pub(crate) mod upstream_oauth2;
pub(crate) mod user_agent;
pub(crate) mod users;

/// Error when an invalid state transition is attempted.
#[derive(Debug, Error)]
#[error("invalid state transition")]
pub struct InvalidTransitionError;

pub use ulid::Ulid;

pub use self::{
    compat::{
        CompatAccessToken, CompatRefreshToken, CompatRefreshTokenState, CompatSession,
        CompatSessionState, CompatSsoLogin, CompatSsoLoginState, Device,
    },
    oauth2::{
        AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, DeviceCodeGrant,
        DeviceCodeGrantState, InvalidRedirectUriError, JwksOrJwksUri, Pkce, Session, SessionState,
    },
    site_config::{CaptchaConfig, CaptchaService, SiteConfig},
    tokens::{
        AccessToken, AccessTokenState, RefreshToken, RefreshTokenState, TokenFormatError, TokenType,
    },
    upstream_oauth2::{
        UpsreamOAuthProviderSetEmailVerification, UpstreamOAuthAuthorizationSession,
        UpstreamOAuthAuthorizationSessionState, UpstreamOAuthLink, UpstreamOAuthProvider,
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderImportAction, UpstreamOAuthProviderImportPreference,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderResponseMode,
        UpstreamOAuthProviderSubjectPreference, UpstreamOAuthProviderTokenAuthMethod,
    },
    user_agent::{DeviceType, UserAgent},
    users::{
        Authentication, AuthenticationMethod, BrowserSession, Password, User, UserEmail,
        UserEmailVerification, UserEmailVerificationState, UserRecoverySession, UserRecoveryTicket,
    },
};
