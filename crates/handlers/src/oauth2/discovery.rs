// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{Json, extract::State, response::IntoResponse};
use mas_iana::oauth::{
    OAuthAuthorizationEndpointResponseType, OAuthClientAuthenticationMethod,
    PkceCodeChallengeMethod,
};
use mas_jose::jwa::SUPPORTED_SIGNING_ALGORITHMS;
use mas_keystore::Keystore;
use mas_router::UrlBuilder;
use oauth2_types::{
    oidc::{ClaimType, ProviderMetadata, SubjectType},
    requests::{Display, GrantType, Prompt, ResponseMode},
    scope,
};
use serde::Serialize;

use crate::SiteConfig;

#[derive(Debug, Serialize)]
struct DiscoveryResponse {
    #[serde(flatten)]
    standard: ProviderMetadata,

    #[serde(rename = "org.matrix.matrix-authentication-service.graphql_endpoint")]
    graphql_endpoint: url::Url,

    // As per MSC2965
    account_management_uri: url::Url,
    account_management_actions_supported: Vec<String>,
}

#[tracing::instrument(name = "handlers.oauth2.discovery.get", skip_all)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn get(
    State(key_store): State<Keystore>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
) -> impl IntoResponse {
    // This is how clients can authenticate
    let client_auth_methods_supported = Some(vec![
        OAuthClientAuthenticationMethod::ClientSecretBasic,
        OAuthClientAuthenticationMethod::ClientSecretPost,
        OAuthClientAuthenticationMethod::ClientSecretJwt,
        OAuthClientAuthenticationMethod::PrivateKeyJwt,
        OAuthClientAuthenticationMethod::None,
    ]);

    // Those are the algorithms supported by `mas-jose`
    let client_auth_signing_alg_values_supported = Some(SUPPORTED_SIGNING_ALGORITHMS.to_vec());

    // This is how we can sign stuff
    let jwt_signing_alg_values_supported = Some(key_store.available_signing_algorithms());

    // Prepare all the endpoints
    let issuer = Some(url_builder.oidc_issuer().into());
    let authorization_endpoint = Some(url_builder.oauth_authorization_endpoint());
    let token_endpoint = Some(url_builder.oauth_token_endpoint());
    let device_authorization_endpoint = Some(url_builder.oauth_device_authorization_endpoint());
    let jwks_uri = Some(url_builder.jwks_uri());
    let introspection_endpoint = Some(url_builder.oauth_introspection_endpoint());
    let revocation_endpoint = Some(url_builder.oauth_revocation_endpoint());
    let userinfo_endpoint = Some(url_builder.oidc_userinfo_endpoint());
    let registration_endpoint = Some(url_builder.oauth_registration_endpoint());

    let scopes_supported = Some(vec![scope::OPENID.to_string(), scope::EMAIL.to_string()]);

    let response_types_supported = Some(vec![
        OAuthAuthorizationEndpointResponseType::Code.into(),
        OAuthAuthorizationEndpointResponseType::IdToken.into(),
        OAuthAuthorizationEndpointResponseType::CodeIdToken.into(),
    ]);

    let response_modes_supported = Some(vec![
        ResponseMode::FormPost,
        ResponseMode::Query,
        ResponseMode::Fragment,
    ]);

    let grant_types_supported = Some(vec![
        GrantType::AuthorizationCode,
        GrantType::RefreshToken,
        GrantType::ClientCredentials,
        GrantType::DeviceCode,
    ]);

    let token_endpoint_auth_methods_supported = client_auth_methods_supported.clone();
    let token_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported.clone();

    let revocation_endpoint_auth_methods_supported = client_auth_methods_supported.clone();
    let revocation_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported.clone();

    let introspection_endpoint_auth_methods_supported =
        client_auth_methods_supported.map(|v| v.into_iter().map(Into::into).collect());
    let introspection_endpoint_auth_signing_alg_values_supported =
        client_auth_signing_alg_values_supported;

    let code_challenge_methods_supported = Some(vec![
        PkceCodeChallengeMethod::Plain,
        PkceCodeChallengeMethod::S256,
    ]);

    let subject_types_supported = Some(vec![SubjectType::Public]);

    let id_token_signing_alg_values_supported = jwt_signing_alg_values_supported.clone();
    let userinfo_signing_alg_values_supported = jwt_signing_alg_values_supported;

    let display_values_supported = Some(vec![Display::Page]);

    let claim_types_supported = Some(vec![ClaimType::Normal]);

    let claims_supported = Some(vec![
        "iss".to_owned(),
        "sub".to_owned(),
        "aud".to_owned(),
        "iat".to_owned(),
        "exp".to_owned(),
        "nonce".to_owned(),
        "auth_time".to_owned(),
        "at_hash".to_owned(),
        "c_hash".to_owned(),
    ]);

    let claims_parameter_supported = Some(false);
    let request_parameter_supported = Some(false);
    let request_uri_parameter_supported = Some(false);

    let prompt_values_supported = Some({
        let mut v = vec![Prompt::Login];
        // Advertise for prompt=create if password registration is enabled
        // TODO: we may want to be able to forward that to upstream providers if they
        // support it
        if site_config.password_registration_enabled {
            v.push(Prompt::Create);
        }
        v
    });

    let standard = ProviderMetadata {
        issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        registration_endpoint,
        scopes_supported,
        response_types_supported,
        response_modes_supported,
        grant_types_supported,
        token_endpoint_auth_methods_supported,
        token_endpoint_auth_signing_alg_values_supported,
        revocation_endpoint,
        revocation_endpoint_auth_methods_supported,
        revocation_endpoint_auth_signing_alg_values_supported,
        introspection_endpoint,
        introspection_endpoint_auth_methods_supported,
        introspection_endpoint_auth_signing_alg_values_supported,
        code_challenge_methods_supported,
        userinfo_endpoint,
        subject_types_supported,
        id_token_signing_alg_values_supported,
        userinfo_signing_alg_values_supported,
        display_values_supported,
        claim_types_supported,
        claims_supported,
        claims_parameter_supported,
        request_parameter_supported,
        request_uri_parameter_supported,
        prompt_values_supported,
        device_authorization_endpoint,
        ..ProviderMetadata::default()
    };

    Json(DiscoveryResponse {
        standard,
        graphql_endpoint: url_builder.graphql_endpoint(),
        account_management_uri: url_builder.account_management_uri(),
        // This needs to be kept in sync with what is supported in the frontend,
        // see frontend/src/routes/__root.tsx
        account_management_actions_supported: vec![
            "org.matrix.profile".to_owned(),
            "org.matrix.sessions_list".to_owned(),
            "org.matrix.session_view".to_owned(),
            "org.matrix.session_end".to_owned(),
            "org.matrix.cross_signing_reset".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use oauth2_types::oidc::ProviderMetadata;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_valid_discovery_metadata(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let request = Request::get("/.well-known/openid-configuration").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let metadata: ProviderMetadata = response.json();
        metadata
            .validate(state.url_builder.oidc_issuer().as_str())
            .expect("Invalid metadata");
    }
}
