// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod add;
mod get;
mod list;

pub use self::{
    add::{doc as add_doc, handler as add},
    get::{doc as get_doc, handler as get},
    list::{doc as list_doc, handler as list},
};

#[cfg(test)]
mod test_utils {
    use mas_data_model::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderDiscoveryMode,
        UpstreamOAuthProviderPkceMode, UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_storage::upstream_oauth2::UpstreamOAuthProviderParams;
    use oauth2_types::scope::{OPENID, Scope};

    pub(crate) fn oidc_provider_params(name: &str) -> UpstreamOAuthProviderParams {
        UpstreamOAuthProviderParams {
            issuer: Some(format!("https://{name}.example.com")),
            human_name: Some(name.to_owned()),
            brand_name: Some(name.to_owned()),
            scope: Scope::from_iter([OPENID]),
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic,
            token_endpoint_signing_alg: None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            fetch_userinfo: false,
            userinfo_signed_response_alg: None,
            client_id: format!("client_{name}"),
            encrypted_client_secret: Some("secret".to_owned()),
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            discovery_mode: UpstreamOAuthProviderDiscoveryMode::default(),
            pkce_mode: UpstreamOAuthProviderPkceMode::default(),
            response_mode: None,
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            jwks_uri_override: None,
            additional_authorization_parameters: Vec::new(),
            ui_order: 0,
        }
    }
}
