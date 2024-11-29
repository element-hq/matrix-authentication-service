// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Table and column identifiers used by [`sea_query`]

#[derive(sea_query::Iden)]
pub enum UserSessions {
    Table,
    UserSessionId,
    UserId,
    CreatedAt,
    FinishedAt,
    UserAgent,
    LastActiveAt,
    LastActiveIp,
}

#[derive(sea_query::Iden)]
pub enum Users {
    Table,
    UserId,
    Username,
    PrimaryUserEmailId,
    CreatedAt,
    LockedAt,
    CanRequestAdmin,
}

#[derive(sea_query::Iden)]
pub enum UserEmails {
    Table,
    UserEmailId,
    UserId,
    Email,
    CreatedAt,
    ConfirmedAt,
}

#[derive(sea_query::Iden)]
pub enum CompatSessions {
    Table,
    CompatSessionId,
    UserId,
    DeviceId,
    UserSessionId,
    CreatedAt,
    FinishedAt,
    IsSynapseAdmin,
    UserAgent,
    LastActiveAt,
    LastActiveIp,
}

#[derive(sea_query::Iden)]
pub enum CompatSsoLogins {
    Table,
    CompatSsoLoginId,
    RedirectUri,
    LoginToken,
    CompatSessionId,
    CreatedAt,
    FulfilledAt,
    ExchangedAt,
}

#[derive(sea_query::Iden)]
#[iden = "oauth2_sessions"]
pub enum OAuth2Sessions {
    Table,
    #[iden = "oauth2_session_id"]
    OAuth2SessionId,
    UserId,
    UserSessionId,
    #[iden = "oauth2_client_id"]
    OAuth2ClientId,
    ScopeList,
    CreatedAt,
    FinishedAt,
    UserAgent,
    LastActiveAt,
    LastActiveIp,
}

#[derive(sea_query::Iden)]
#[iden = "upstream_oauth_providers"]
pub enum UpstreamOAuthProviders {
    Table,
    #[iden = "upstream_oauth_provider_id"]
    UpstreamOAuthProviderId,
    Issuer,
    HumanName,
    BrandName,
    Scope,
    ClientId,
    EncryptedClientSecret,
    TokenEndpointSigningAlg,
    TokenEndpointAuthMethod,
    FetchUserinfo,
    CreatedAt,
    DisabledAt,
    ClaimsImports,
    DiscoveryMode,
    PkceMode,
    ResponseMode,
    AdditionalParameters,
    JwksUriOverride,
    TokenEndpointOverride,
    AuthorizationEndpointOverride,
    UserinfoEndpointOverride,
}

#[derive(sea_query::Iden)]
#[iden = "upstream_oauth_links"]
pub enum UpstreamOAuthLinks {
    Table,
    #[iden = "upstream_oauth_link_id"]
    UpstreamOAuthLinkId,
    #[iden = "upstream_oauth_provider_id"]
    UpstreamOAuthProviderId,
    UserId,
    Subject,
    HumanAccountName,
    CreatedAt,
}
