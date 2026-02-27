// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(clippy::module_name_repetitions)]

use thiserror::Error;

pub mod clock;
pub(crate) mod compat;
pub mod oauth2;
pub mod personal;
pub(crate) mod policy_data;
mod site_config;
pub(crate) mod tokens;
pub(crate) mod upstream_oauth2;
pub(crate) mod user_agent;
pub(crate) mod users;
mod utils;
mod version;

/// Error when an invalid state transition is attempted.
#[derive(Debug, Error)]
#[error("invalid state transition")]
pub struct InvalidTransitionError;

pub use ulid::Ulid;

pub use self::{
    clock::{Clock, SystemClock},
    compat::{
        CompatAccessToken, CompatRefreshToken, CompatRefreshTokenState, CompatSession,
        CompatSessionState, CompatSsoLogin, CompatSsoLoginState, Device, ToScopeTokenError,
    },
    oauth2::{
        AuthorizationCode, AuthorizationGrant, AuthorizationGrantStage, Client, DeviceCodeGrant,
        DeviceCodeGrantState, InvalidRedirectUriError, JwksOrJwksUri, Pkce, Session, SessionState,
    },
    policy_data::PolicyData,
    site_config::{
        CaptchaConfig, CaptchaService, SessionExpirationConfig, SessionLimitConfig, SiteConfig,
    },
    tokens::{
        AccessToken, AccessTokenState, RefreshToken, RefreshTokenState, TokenFormatError, TokenType,
    },
    upstream_oauth2::{
        UpstreamOAuthAuthorizationSession, UpstreamOAuthAuthorizationSessionState,
        UpstreamOAuthLink, UpstreamOAuthLinkToken, UpstreamOAuthProvider,
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderImportAction, UpstreamOAuthProviderImportPreference,
        UpstreamOAuthProviderLocalpartPreference, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderOnConflict, UpstreamOAuthProviderPkceMode,
        UpstreamOAuthProviderResponseMode, UpstreamOAuthProviderSubjectPreference,
        UpstreamOAuthProviderTokenAuthMethod,
    },
    user_agent::{DeviceType, UserAgent},
    users::{
        Authentication, AuthenticationMethod, BrowserSession, MatrixUser, Password, User,
        UserEmail, UserEmailAuthentication, UserEmailAuthenticationCode, UserRecoverySession,
        UserRecoveryTicket, UserRegistration, UserRegistrationPassword, UserRegistrationToken,
    },
    utils::{BoxClock, BoxRng},
    version::AppVersion,
};
