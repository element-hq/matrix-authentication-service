// Copyright (C) 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Repositories to interact with entities related to the OAuth 2.0 protocol

mod access_token;
mod authorization_grant;
mod client;
mod device_code_grant;
mod refresh_token;
mod session;

pub use self::{
    access_token::OAuth2AccessTokenRepository,
    authorization_grant::OAuth2AuthorizationGrantRepository,
    client::OAuth2ClientRepository,
    device_code_grant::{OAuth2DeviceCodeGrantParams, OAuth2DeviceCodeGrantRepository},
    refresh_token::OAuth2RefreshTokenRepository,
    session::{OAuth2SessionFilter, OAuth2SessionRepository},
};
