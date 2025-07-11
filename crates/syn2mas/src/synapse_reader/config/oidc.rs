// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::BTreeMap, str::FromStr as _};

use chrono::{DateTime, Utc};
use mas_config::{
    UpstreamOAuth2ClaimsImports, UpstreamOAuth2DiscoveryMode, UpstreamOAuth2ImportAction,
    UpstreamOAuth2OnBackchannelLogout, UpstreamOAuth2PkceMethod, UpstreamOAuth2ResponseMode,
    UpstreamOAuth2TokenAuthMethod,
};
use mas_iana::jose::JsonWebSignatureAlg;
use oauth2_types::scope::{OPENID, Scope, ScopeToken};
use rand::Rng;
use serde::Deserialize;
use tracing::warn;
use ulid::Ulid;
use url::Url;

#[derive(Clone, Deserialize, Default)]
enum UserMappingProviderModule {
    #[default]
    #[serde(rename = "synapse.handlers.oidc.JinjaOidcMappingProvider")]
    Jinja,

    #[serde(rename = "synapse.handlers.oidc_handler.JinjaOidcMappingProvider")]
    JinjaLegacy,

    #[serde(other)]
    Other,
}

#[derive(Clone, Deserialize, Default)]
struct UserMappingProviderConfig {
    subject_template: Option<String>,
    subject_claim: Option<String>,
    localpart_template: Option<String>,
    display_name_template: Option<String>,
    email_template: Option<String>,

    #[serde(default)]
    confirm_localpart: bool,
}

impl UserMappingProviderConfig {
    fn into_mas_config(self) -> UpstreamOAuth2ClaimsImports {
        let mut config = UpstreamOAuth2ClaimsImports::default();

        match (self.subject_claim, self.subject_template) {
            (Some(_), Some(subject_template)) => {
                warn!(
                    "Both `subject_claim` and `subject_template` options are set, using `subject_template`."
                );
                config.subject.template = Some(subject_template);
            }
            (None, Some(subject_template)) => {
                config.subject.template = Some(subject_template);
            }
            (Some(subject_claim), None) => {
                config.subject.template = Some(format!("{{{{ user.{subject_claim} }}}}"));
            }
            (None, None) => {}
        }

        if let Some(localpart_template) = self.localpart_template {
            config.localpart.template = Some(localpart_template);
            config.localpart.action = if self.confirm_localpart {
                UpstreamOAuth2ImportAction::Suggest
            } else {
                UpstreamOAuth2ImportAction::Require
            };
        }

        if let Some(displayname_template) = self.display_name_template {
            config.displayname.template = Some(displayname_template);
            config.displayname.action = if self.confirm_localpart {
                UpstreamOAuth2ImportAction::Suggest
            } else {
                UpstreamOAuth2ImportAction::Force
            };
        }

        if let Some(email_template) = self.email_template {
            config.email.template = Some(email_template);
            config.email.action = if self.confirm_localpart {
                UpstreamOAuth2ImportAction::Suggest
            } else {
                UpstreamOAuth2ImportAction::Force
            };
        }

        config
    }
}

#[derive(Clone, Deserialize, Default)]
struct UserMappingProvider {
    #[serde(default)]
    module: UserMappingProviderModule,
    #[serde(default)]
    config: UserMappingProviderConfig,
}

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
enum PkceMethod {
    #[default]
    Auto,
    Always,
    Never,
    #[serde(other)]
    Other,
}

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum UserProfileMethod {
    #[default]
    Auto,
    UserinfoEndpoint,
    #[serde(other)]
    Other,
}

#[derive(Clone, Deserialize)]
#[expect(clippy::struct_excessive_bools)]
pub struct OidcProvider {
    pub issuer: Option<String>,

    /// Required, except for the old `oidc_config` where this is implied to be
    /// "oidc".
    pub idp_id: Option<String>,

    idp_name: Option<String>,
    idp_brand: Option<String>,

    #[serde(default = "default_true")]
    discover: bool,

    client_id: Option<String>,
    client_secret: Option<String>,

    // Unsupported, we want to shout about it
    client_secret_path: Option<String>,

    // Unsupported, we want to shout about it
    client_secret_jwt_key: Option<serde_json::Value>,
    client_auth_method: Option<UpstreamOAuth2TokenAuthMethod>,
    #[serde(default)]
    pkce_method: PkceMethod,
    // Unsupported, we want to shout about it
    id_token_signing_alg_values_supported: Option<Vec<String>>,
    scopes: Option<Vec<String>>,
    authorization_endpoint: Option<Url>,
    token_endpoint: Option<Url>,
    userinfo_endpoint: Option<Url>,
    jwks_uri: Option<Url>,
    #[serde(default)]
    skip_verification: bool,

    #[serde(default)]
    backchannel_logout_enabled: bool,

    #[serde(default)]
    user_profile_method: UserProfileMethod,

    // Unsupported, we want to shout about it
    attribute_requirements: Option<serde_json::Value>,

    // Unsupported, we want to shout about it
    #[serde(default = "default_true")]
    enable_registration: bool,
    #[serde(default)]
    additional_authorization_parameters: BTreeMap<String, String>,
    #[serde(default)]
    forward_login_hint: bool,
    #[serde(default)]
    user_mapping_provider: UserMappingProvider,
}

fn default_true() -> bool {
    true
}

impl OidcProvider {
    /// Returns true if the two 'required' fields are set. This is used to
    /// ignore an empty dict on the `oidc_config` section.
    #[must_use]
    pub(crate) fn has_required_fields(&self) -> bool {
        self.issuer.is_some() && self.client_id.is_some()
    }

    /// Map this Synapse OIDC provider config to a MAS upstream provider config.
    #[expect(clippy::too_many_lines)]
    pub(crate) fn into_mas_config(
        self,
        rng: &mut impl Rng,
        now: DateTime<Utc>,
    ) -> Option<mas_config::UpstreamOAuth2Provider> {
        let client_id = self.client_id?;

        if self.client_secret_path.is_some() {
            warn!(
                "The `client_secret_path` option is not supported, ignoring. You *will* need to include the secret in the `client_secret` field."
            );
        }

        if self.client_secret_jwt_key.is_some() {
            warn!("The `client_secret_jwt_key` option is not supported, ignoring.");
        }

        if self.attribute_requirements.is_some() {
            warn!("The `attribute_requirements` option is not supported, ignoring.");
        }

        if self.id_token_signing_alg_values_supported.is_some() {
            warn!("The `id_token_signing_alg_values_supported` option is not supported, ignoring.");
        }

        if !self.enable_registration {
            warn!(
                "Setting the `enable_registration` option to `false` is not supported, ignoring."
            );
        }

        let scope: Scope = match self.scopes {
            None => [OPENID].into_iter().collect(), // Synapse defaults to the 'openid' scope
            Some(scopes) => scopes
                .into_iter()
                .filter_map(|scope| match ScopeToken::from_str(&scope) {
                    Ok(scope) => Some(scope),
                    Err(err) => {
                        warn!("OIDC provider scope '{scope}' is invalid: {err}");
                        None
                    }
                })
                .collect(),
        };

        let id = Ulid::from_datetime_with_source(now.into(), rng);

        let token_endpoint_auth_method = self.client_auth_method.unwrap_or_else(|| {
            // The token auth method defaults to 'none' if no client_secret is set and
            // 'client_secret_basic' otherwise
            if self.client_secret.is_some() {
                UpstreamOAuth2TokenAuthMethod::ClientSecretBasic
            } else {
                UpstreamOAuth2TokenAuthMethod::None
            }
        });

        let discovery_mode = match (self.discover, self.skip_verification) {
            (true, false) => UpstreamOAuth2DiscoveryMode::Oidc,
            (true, true) => UpstreamOAuth2DiscoveryMode::Insecure,
            (false, _) => UpstreamOAuth2DiscoveryMode::Disabled,
        };

        let pkce_method = match self.pkce_method {
            PkceMethod::Auto => UpstreamOAuth2PkceMethod::Auto,
            PkceMethod::Always => UpstreamOAuth2PkceMethod::Always,
            PkceMethod::Never => UpstreamOAuth2PkceMethod::Never,
            PkceMethod::Other => {
                warn!(
                    "The `pkce_method` option is not supported, expected 'auto', 'always', or 'never'; assuming 'auto'."
                );
                UpstreamOAuth2PkceMethod::default()
            }
        };

        // "auto" doesn't mean the same thing depending on whether we request the openid
        // scope or not
        let has_openid_scope = scope.contains(&OPENID);
        let fetch_userinfo = match self.user_profile_method {
            UserProfileMethod::Auto => has_openid_scope,
            UserProfileMethod::UserinfoEndpoint => true,
            UserProfileMethod::Other => {
                warn!(
                    "The `user_profile_method` option is not supported, expected 'auto' or 'userinfo_endpoint'; assuming 'auto'."
                );
                has_openid_scope
            }
        };

        // Check if there is a `response_mode` set in the additional authorization
        // parameters
        let mut additional_authorization_parameters = self.additional_authorization_parameters;
        let response_mode = if let Some(response_mode) =
            additional_authorization_parameters.remove("response_mode")
        {
            match response_mode.to_ascii_lowercase().as_str() {
                "query" => Some(UpstreamOAuth2ResponseMode::Query),
                "form_post" => Some(UpstreamOAuth2ResponseMode::FormPost),
                _ => {
                    warn!(
                        "Invalid `response_mode` in the `additional_authorization_parameters` option, expected 'query' or 'form_post'; ignoring."
                    );
                    None
                }
            }
        } else {
            None
        };

        let claims_imports = if matches!(
            self.user_mapping_provider.module,
            UserMappingProviderModule::Other
        ) {
            warn!(
                "The `user_mapping_provider` module specified is not supported, ignoring. Please adjust the `claims_imports` to match the mapping provider behaviour."
            );
            UpstreamOAuth2ClaimsImports::default()
        } else {
            self.user_mapping_provider.config.into_mas_config()
        };

        let on_backchannel_logout = if self.backchannel_logout_enabled {
            UpstreamOAuth2OnBackchannelLogout::DoNothing
        } else {
            UpstreamOAuth2OnBackchannelLogout::LogoutBrowserOnly
        };

        Some(mas_config::UpstreamOAuth2Provider {
            enabled: true,
            id,
            synapse_idp_id: self.idp_id,
            issuer: self.issuer,
            human_name: self.idp_name,
            brand_name: self.idp_brand,
            client_id,
            client_secret: self.client_secret,
            token_endpoint_auth_method,
            sign_in_with_apple: None,
            token_endpoint_auth_signing_alg: None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            scope: scope.to_string(),
            discovery_mode,
            pkce_method,
            fetch_userinfo,
            userinfo_signed_response_alg: None,
            authorization_endpoint: self.authorization_endpoint,
            userinfo_endpoint: self.userinfo_endpoint,
            token_endpoint: self.token_endpoint,
            jwks_uri: self.jwks_uri,
            response_mode,
            claims_imports,
            additional_authorization_parameters,
            forward_login_hint: self.forward_login_hint,
            on_backchannel_logout,
        })
    }
}
