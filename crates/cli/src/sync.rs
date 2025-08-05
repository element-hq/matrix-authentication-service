// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Utilities to synchronize the configuration file with the database.

use std::collections::{BTreeMap, BTreeSet};

use mas_config::{ClientsConfig, UpstreamOAuth2Config};
use mas_data_model::Clock;
use mas_keystore::Encrypter;
use mas_storage::{
    Pagination, RepositoryAccess,
    upstream_oauth2::{UpstreamOAuthProviderFilter, UpstreamOAuthProviderParams},
};
use mas_storage_pg::PgRepository;
use sqlx::{Connection, PgConnection, postgres::PgAdvisoryLock};
use tracing::{error, info, info_span, warn};

fn map_import_action(
    config: mas_config::UpstreamOAuth2ImportAction,
) -> mas_data_model::UpstreamOAuthProviderImportAction {
    match config {
        mas_config::UpstreamOAuth2ImportAction::Ignore => {
            mas_data_model::UpstreamOAuthProviderImportAction::Ignore
        }
        mas_config::UpstreamOAuth2ImportAction::Suggest => {
            mas_data_model::UpstreamOAuthProviderImportAction::Suggest
        }
        mas_config::UpstreamOAuth2ImportAction::Force => {
            mas_data_model::UpstreamOAuthProviderImportAction::Force
        }
        mas_config::UpstreamOAuth2ImportAction::Require => {
            mas_data_model::UpstreamOAuthProviderImportAction::Require
        }
    }
}

fn map_import_on_conflict(
    config: mas_config::UpstreamOAuth2OnConflict,
) -> mas_data_model::UpstreamOAuthProviderOnConflict {
    match config {
        mas_config::UpstreamOAuth2OnConflict::Add => {
            mas_data_model::UpstreamOAuthProviderOnConflict::Add
        }
        mas_config::UpstreamOAuth2OnConflict::Fail => {
            mas_data_model::UpstreamOAuthProviderOnConflict::Fail
        }
    }
}

fn map_claims_imports(
    config: &mas_config::UpstreamOAuth2ClaimsImports,
) -> mas_data_model::UpstreamOAuthProviderClaimsImports {
    mas_data_model::UpstreamOAuthProviderClaimsImports {
        subject: mas_data_model::UpstreamOAuthProviderSubjectPreference {
            template: config.subject.template.clone(),
        },
        localpart: mas_data_model::UpstreamOAuthProviderLocalpartPreference {
            action: map_import_action(config.localpart.action),
            template: config.localpart.template.clone(),
            on_conflict: map_import_on_conflict(config.localpart.on_conflict),
        },
        displayname: mas_data_model::UpstreamOAuthProviderImportPreference {
            action: map_import_action(config.displayname.action),
            template: config.displayname.template.clone(),
        },
        email: mas_data_model::UpstreamOAuthProviderImportPreference {
            action: map_import_action(config.email.action),
            template: config.email.template.clone(),
        },
        account_name: mas_data_model::UpstreamOAuthProviderSubjectPreference {
            template: config.account_name.template.clone(),
        },
    }
}

#[tracing::instrument(name = "config.sync", skip_all)]
pub async fn config_sync(
    upstream_oauth2_config: UpstreamOAuth2Config,
    clients_config: ClientsConfig,
    connection: &mut PgConnection,
    encrypter: &Encrypter,
    clock: &dyn Clock,
    prune: bool,
    dry_run: bool,
) -> anyhow::Result<()> {
    // Start a transaction
    let txn = connection.begin().await?;

    // Grab a lock within the transaction
    tracing::info!("Acquiring configuration lock");
    let lock = PgAdvisoryLock::new("MAS config sync");
    let lock = lock.acquire(txn).await?;

    // Create a repository from the connection with the lock
    let mut repo = PgRepository::from_conn(lock);

    tracing::info!(
        prune,
        dry_run,
        "Syncing providers and clients defined in config to database"
    );

    {
        let _span = info_span!("cli.config.sync.providers").entered();
        let config_ids = upstream_oauth2_config
            .providers
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.id)
            .collect::<BTreeSet<_>>();

        // Let's assume we have less than 1000 providers
        let page = repo
            .upstream_oauth_provider()
            .list(
                UpstreamOAuthProviderFilter::default(),
                Pagination::first(1000),
            )
            .await?;

        // A warning is probably enough
        if page.has_next_page {
            warn!(
                "More than 1000 providers in the database, only the first 1000 will be considered"
            );
        }

        let mut existing_enabled_ids = BTreeSet::new();
        let mut existing_disabled = BTreeMap::new();
        // Process the existing providers
        for provider in page.edges {
            if provider.enabled() {
                if config_ids.contains(&provider.id) {
                    existing_enabled_ids.insert(provider.id);
                } else {
                    // Provider is enabled in the database but not in the config
                    info!(%provider.id, "Disabling provider");

                    let provider = if dry_run {
                        provider
                    } else {
                        repo.upstream_oauth_provider()
                            .disable(clock, provider)
                            .await?
                    };

                    existing_disabled.insert(provider.id, provider);
                }
            } else {
                existing_disabled.insert(provider.id, provider);
            }
        }

        if prune {
            for provider_id in existing_disabled.keys().copied() {
                info!(provider.id = %provider_id, "Deleting provider");

                if dry_run {
                    continue;
                }

                repo.upstream_oauth_provider()
                    .delete_by_id(provider_id)
                    .await?;
            }
        } else {
            let len = existing_disabled.len();
            match len {
                0 => {}
                1 => warn!(
                    "A provider is soft-deleted in the database. Run `mas-cli config sync --prune` to delete it."
                ),
                n => warn!(
                    "{n} providers are soft-deleted in the database. Run `mas-cli config sync --prune` to delete them."
                ),
            }
        }

        for (index, provider) in upstream_oauth2_config.providers.into_iter().enumerate() {
            if !provider.enabled {
                continue;
            }

            // Use the position in the config of the provider as position in the UI
            let ui_order = index.try_into().unwrap_or(i32::MAX);

            let _span = info_span!("provider", %provider.id).entered();
            if existing_enabled_ids.contains(&provider.id) {
                info!(provider.id = %provider.id, "Updating provider");
            } else if existing_disabled.contains_key(&provider.id) {
                info!(provider.id = %provider.id, "Enabling and updating provider");
            } else {
                info!(provider.id = %provider.id, "Adding provider");
            }

            if dry_run {
                continue;
            }

            let encrypted_client_secret =
                if let Some(client_secret) = provider.client_secret.as_deref() {
                    Some(encrypter.encrypt_to_string(client_secret.as_bytes())?)
                } else if let Some(mut siwa) = provider.sign_in_with_apple.clone() {
                    // if private key file is defined and not private key (raw), we populate the
                    // private key to hold the content of the private key file.
                    // private key (raw) takes precedence so both can be defined
                    // without issues
                    if siwa.private_key.is_none() {
                        if let Some(private_key_file) = siwa.private_key_file.take() {
                            let key = tokio::fs::read_to_string(private_key_file).await?;
                            siwa.private_key = Some(key);
                        }
                    }
                    let encoded = serde_json::to_vec(&siwa)?;
                    Some(encrypter.encrypt_to_string(&encoded)?)
                } else {
                    None
                };

            let discovery_mode = match provider.discovery_mode {
                mas_config::UpstreamOAuth2DiscoveryMode::Oidc => {
                    mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc
                }
                mas_config::UpstreamOAuth2DiscoveryMode::Insecure => {
                    mas_data_model::UpstreamOAuthProviderDiscoveryMode::Insecure
                }
                mas_config::UpstreamOAuth2DiscoveryMode::Disabled => {
                    mas_data_model::UpstreamOAuthProviderDiscoveryMode::Disabled
                }
            };

            let token_endpoint_auth_method = match provider.token_endpoint_auth_method {
                mas_config::UpstreamOAuth2TokenAuthMethod::None => {
                    mas_data_model::UpstreamOAuthProviderTokenAuthMethod::None
                }
                mas_config::UpstreamOAuth2TokenAuthMethod::ClientSecretBasic => {
                    mas_data_model::UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic
                }
                mas_config::UpstreamOAuth2TokenAuthMethod::ClientSecretPost => {
                    mas_data_model::UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost
                }
                mas_config::UpstreamOAuth2TokenAuthMethod::ClientSecretJwt => {
                    mas_data_model::UpstreamOAuthProviderTokenAuthMethod::ClientSecretJwt
                }
                mas_config::UpstreamOAuth2TokenAuthMethod::PrivateKeyJwt => {
                    mas_data_model::UpstreamOAuthProviderTokenAuthMethod::PrivateKeyJwt
                }
                mas_config::UpstreamOAuth2TokenAuthMethod::SignInWithApple => {
                    mas_data_model::UpstreamOAuthProviderTokenAuthMethod::SignInWithApple
                }
            };

            let response_mode = provider
                .response_mode
                .map(|response_mode| match response_mode {
                    mas_config::UpstreamOAuth2ResponseMode::Query => {
                        mas_data_model::UpstreamOAuthProviderResponseMode::Query
                    }
                    mas_config::UpstreamOAuth2ResponseMode::FormPost => {
                        mas_data_model::UpstreamOAuthProviderResponseMode::FormPost
                    }
                });

            if discovery_mode.is_disabled() {
                if provider.authorization_endpoint.is_none() {
                    error!(provider.id = %provider.id, "Provider has discovery disabled but no authorization endpoint set");
                }

                if provider.token_endpoint.is_none() {
                    error!(provider.id = %provider.id, "Provider has discovery disabled but no token endpoint set");
                }

                if provider.jwks_uri.is_none() {
                    warn!(provider.id = %provider.id, "Provider has discovery disabled but no JWKS URI set");
                }
            }

            let pkce_mode = match provider.pkce_method {
                mas_config::UpstreamOAuth2PkceMethod::Auto => {
                    mas_data_model::UpstreamOAuthProviderPkceMode::Auto
                }
                mas_config::UpstreamOAuth2PkceMethod::Always => {
                    mas_data_model::UpstreamOAuthProviderPkceMode::S256
                }
                mas_config::UpstreamOAuth2PkceMethod::Never => {
                    mas_data_model::UpstreamOAuthProviderPkceMode::Disabled
                }
            };

            let on_backchannel_logout = match provider.on_backchannel_logout {
                mas_config::UpstreamOAuth2OnBackchannelLogout::DoNothing => {
                    mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::DoNothing
                }
                mas_config::UpstreamOAuth2OnBackchannelLogout::LogoutBrowserOnly => {
                    mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::LogoutBrowserOnly
                }
                mas_config::UpstreamOAuth2OnBackchannelLogout::LogoutAll => {
                    mas_data_model::UpstreamOAuthProviderOnBackchannelLogout::LogoutAll
                }
            };

            repo.upstream_oauth_provider()
                .upsert(
                    clock,
                    provider.id,
                    UpstreamOAuthProviderParams {
                        issuer: provider.issuer,
                        human_name: provider.human_name,
                        brand_name: provider.brand_name,
                        scope: provider.scope.parse()?,
                        token_endpoint_auth_method,
                        token_endpoint_signing_alg: provider.token_endpoint_auth_signing_alg,
                        id_token_signed_response_alg: provider.id_token_signed_response_alg,
                        client_id: provider.client_id,
                        encrypted_client_secret,
                        claims_imports: map_claims_imports(&provider.claims_imports),
                        token_endpoint_override: provider.token_endpoint,
                        userinfo_endpoint_override: provider.userinfo_endpoint,
                        authorization_endpoint_override: provider.authorization_endpoint,
                        jwks_uri_override: provider.jwks_uri,
                        discovery_mode,
                        pkce_mode,
                        fetch_userinfo: provider.fetch_userinfo,
                        userinfo_signed_response_alg: provider.userinfo_signed_response_alg,
                        response_mode,
                        additional_authorization_parameters: provider
                            .additional_authorization_parameters
                            .into_iter()
                            .collect(),
                        forward_login_hint: provider.forward_login_hint,
                        ui_order,
                        on_backchannel_logout,
                    },
                )
                .await?;
        }
    }

    {
        let _span = info_span!("cli.config.sync.clients").entered();
        let config_ids = clients_config
            .iter()
            .map(|c| c.client_id)
            .collect::<BTreeSet<_>>();

        let existing = repo.oauth2_client().all_static().await?;
        let existing_ids = existing.iter().map(|p| p.id).collect::<BTreeSet<_>>();
        let to_delete = existing.into_iter().filter(|p| !config_ids.contains(&p.id));
        if prune {
            for client in to_delete {
                info!(client.id = %client.client_id, "Deleting client");

                if dry_run {
                    continue;
                }

                repo.oauth2_client().delete(client).await?;
            }
        } else {
            let len = to_delete.count();
            match len {
                0 => {}
                1 => warn!(
                    "A static client in the database is not in the config. Run with `--prune` to delete it."
                ),
                n => warn!(
                    "{n} static clients in the database are not in the config. Run with `--prune` to delete them."
                ),
            }
        }

        for client in clients_config {
            let _span = info_span!("client", client.id = %client.client_id).entered();
            if existing_ids.contains(&client.client_id) {
                info!(client.id = %client.client_id, "Updating client");
            } else {
                info!(client.id = %client.client_id, "Adding client");
            }

            if dry_run {
                continue;
            }

            let client_secret = client.client_secret().await?;
            let client_name = client.client_name.as_ref();
            let client_auth_method = client.client_auth_method();
            let jwks = client.jwks.as_ref();
            let jwks_uri = client.jwks_uri.as_ref();

            // TODO: should be moved somewhere else
            let encrypted_client_secret = client_secret
                .map(|client_secret| encrypter.encrypt_to_string(client_secret.as_bytes()))
                .transpose()?;

            repo.oauth2_client()
                .upsert_static(
                    client.client_id,
                    client_name.cloned(),
                    client_auth_method,
                    encrypted_client_secret,
                    jwks.cloned(),
                    jwks_uri.cloned(),
                    client.redirect_uris,
                )
                .await?;
        }
    }

    // Get the lock and release it to commit the transaction
    let lock = repo.into_inner();
    let txn = lock.release_now().await?;
    if dry_run {
        info!("Dry run, rolling back changes");
        txn.rollback().await?;
    } else {
        txn.commit().await?;
    }
    Ok(())
}
