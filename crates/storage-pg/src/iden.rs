// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

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
    CreatedAt,
    LockedAt,
    DeactivatedAt,
    CanRequestAdmin,
    IsGuest,
}

#[derive(sea_query::Iden)]
pub enum UserEmails {
    Table,
    UserEmailId,
    UserId,
    Email,
    CreatedAt,
}

#[derive(sea_query::Iden)]
pub enum CompatSessions {
    Table,
    CompatSessionId,
    UserId,
    DeviceId,
    HumanName,
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
    UserSessionId,
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
    HumanName,
}

#[derive(sea_query::Iden)]
#[iden = "oauth2_clients"]
pub enum OAuth2Clients {
    Table,
    #[iden = "oauth2_client_id"]
    OAuth2ClientId,
    IsStatic,
}

#[derive(sea_query::Iden)]
#[iden = "personal_sessions"]
pub enum PersonalSessions {
    Table,
    PersonalSessionId,
    OwnerUserId,
    #[iden = "owner_oauth2_client_id"]
    OwnerOAuth2ClientId,
    ActorUserId,
    HumanName,
    ScopeList,
    CreatedAt,
    RevokedAt,
    LastActiveAt,
    LastActiveIp,
}

#[derive(sea_query::Iden)]
#[iden = "personal_access_tokens"]
pub enum PersonalAccessTokens {
    Table,
    PersonalAccessTokenId,
    PersonalSessionId,
    // AccessTokenSha256,
    CreatedAt,
    ExpiresAt,
    RevokedAt,
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
    IdTokenSignedResponseAlg,
    FetchUserinfo,
    UserinfoSignedResponseAlg,
    CreatedAt,
    DisabledAt,
    ClaimsImports,
    DiscoveryMode,
    PkceMode,
    ResponseMode,
    AdditionalParameters,
    ForwardLoginHint,
    JwksUriOverride,
    TokenEndpointOverride,
    AuthorizationEndpointOverride,
    UserinfoEndpointOverride,
    OnBackchannelLogout,
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

#[derive(sea_query::Iden)]
#[iden = "upstream_oauth_authorization_sessions"]
pub enum UpstreamOAuthAuthorizationSessions {
    Table,
    #[iden = "upstream_oauth_authorization_session_id"]
    UpstreamOAuthAuthorizationSessionId,
    #[iden = "upstream_oauth_provider_id"]
    UpstreamOAuthProviderId,
    #[iden = "upstream_oauth_link_id"]
    UpstreamOAuthLinkId,
    State,
    CodeChallengeVerifier,
    Nonce,
    IdToken,
    IdTokenClaims,
    ExtraCallbackParameters,
    Userinfo,
    CreatedAt,
    CompletedAt,
    ConsumedAt,
    UnlinkedAt,
    UserSessionId,
}

#[derive(sea_query::Iden)]
pub enum UserRegistrationTokens {
    Table,
    UserRegistrationTokenId,
    Token,
    UsageLimit,
    TimesUsed,
    CreatedAt,
    LastUsedAt,
    ExpiresAt,
    RevokedAt,
}

#[derive(sea_query::Iden)]
pub enum UserPasskeys {
    Table,
    UserPasskeyId,
    UserId,
    CredentialId,
    Name,
    Transports,
    StaticState,
    DynamicState,
    Metadata,
    LastUsedAt,
    CreatedAt,
}
