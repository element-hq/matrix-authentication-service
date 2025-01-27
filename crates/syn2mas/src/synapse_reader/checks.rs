// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # Synapse Checks
//!
//! This module provides safety checks to run against a Synapse database before running the Synapse-to-MAS migration.

use figment::Figment;
use mas_config::{
    BrandingConfig, CaptchaConfig, ConfigurationSection, ConfigurationSectionExt, MatrixConfig,
    PasswordAlgorithm, PasswordsConfig, UpstreamOAuth2Config,
};
use sqlx::{prelude::FromRow, query_as, query_scalar, PgConnection};
use thiserror::Error;

use crate::mas_writer::MIGRATED_PASSWORD_VERSION;

use super::config::Config;

#[derive(Debug, Error)]
pub enum Error {
    #[error("query failed: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("failed to load MAS config: {0}")]
    MasConfig(#[from] figment::Error),

    #[error("failed to load MAS password config: {0}")]
    MasPasswordConfig(#[source] anyhow::Error),
}

/// An error found whilst checking the Synapse database, that should block a migration.
#[derive(Debug, Error)]
pub enum CheckError {
    #[error("MAS config is missing a password hashing scheme with version '1'")]
    MissingPasswordScheme,

    #[error("Password scheme version '1' in the MAS config must use the Bcrypt algorithm, so that Synapse passwords can be imported and will be compatible.")]
    PasswordSchemeNotBcrypt,

    #[error("Password scheme version '1' in the MAS config must have the same secret as the `pepper` value from Synapse, so that Synapse passwords can be imported and will be compatible.")]
    PasswordSchemeWrongPepper,

    #[error("Synapse database contains {num_guests} guests which aren't supported by MAS. See https://github.com/element-hq/matrix-authentication-service/issues/1445")]
    GuestsInDatabase { num_guests: i64 },

    #[error("Guest support is enabled in the Synapse configuration. Guests aren't supported by MAS, but if you don't have any then you could disable the option. See https://github.com/element-hq/matrix-authentication-service/issues/1445")]
    GuestsEnabled,

    #[error("Synapse database contains {num_non_email_3pids} non-email 3PIDs (probably phone numbers), which are not supported by MAS.")]
    NonEmailThreepidsInDatabase { num_non_email_3pids: i64 },

    #[error(
        "Synapse config has `enable_3pid_changes` explicitly enabled, which must be disabled or removed."
    )]
    ThreepidChangesEnabled,

    #[error("Synapse config has `login_via_existing_session.enabled` set to true, which must be disabled.")]
    LoginViaExistingSessionEnabled,

    #[error("MAS configuration has the wrong `matrix.homeserver` set ({mas:?}), it should match Synapse's `server_name` ({synapse:?})")]
    ServerNameMismatch { synapse: String, mas: String },

    #[error("Synapse database contains {num_users} users associated to the OpenID Connect or OAuth2 provider '{provider}' but the Synapse configuration does not contain this provider.")]
    SynapseMissingOAuthProvider { provider: String, num_users: i64 },

    #[error("Synapse config contains an OpenID Connect or OAuth2 provider '{provider}' (issuer: {issuer:?}) used by {num_users} users which must also be configured in the MAS configuration as an upstream provider.")]
    MasMissingOAuthProvider {
        provider: String,
        issuer: String,
        num_users: i64,
    },
}

/// A potential hazard found whilst checking the Synapse database, that should be presented
/// to the operator to check they are aware of a caveat before proceeding with the migration.
#[derive(Debug, Error)]
pub enum CheckWarning {
    #[error("Synapse config contains OIDC auth configuration (issuer: {issuer:?}) which will need to be manually mapped to an upstream OpenID Connect Provider during migration.")]
    UpstreamOidcProvider { issuer: String },

    #[error("Synapse config contains {0} auth configuration which will need to be manually mapped as an upstream OAuth 2.0 provider during migration.")]
    ExternalAuthSystem(&'static str),

    #[error("Synapse config has registration enabled. This must be disabled after migration before bringing Synapse back online.")]
    DisableRegistrationAfterMigration,

    #[error("Synapse config has `user_consent` enabled. This should be disabled after migration.")]
    DisableUserConsentAfterMigration,

    #[error("Synapse config has `user_consent` enabled but MAS has not been configured with terms of service. You may wish to set up a `tos_uri` in your MAS branding configuration to replace the user consent.")]
    ShouldPortUserConsentAsTerms,

    #[error("Synapse config has a registration CAPTCHA enabled, but no CAPTCHA has been configured in MAS. You may wish to manually configure this.")]
    ShouldPortRegistrationCaptcha,
}

/// Check that the Synapse configuration is sane for migration.
#[must_use]
pub fn synapse_config_check(synapse_config: &Config) -> (Vec<CheckWarning>, Vec<CheckError>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if synapse_config.enable_registration {
        warnings.push(CheckWarning::DisableRegistrationAfterMigration);
    }
    if synapse_config.user_consent {
        warnings.push(CheckWarning::DisableUserConsentAfterMigration);
    }

    // TODO check the settings directly against the MAS settings
    for provider in synapse_config.all_oidc_providers().values() {
        if let Some(ref issuer) = provider.issuer {
            warnings.push(CheckWarning::UpstreamOidcProvider {
                issuer: issuer.clone(),
            });
        }
    }

    // TODO provide guidance on migrating these
    if synapse_config.cas_config.enabled {
        warnings.push(CheckWarning::ExternalAuthSystem("CAS"));
    }
    if synapse_config.saml2_config.enabled {
        warnings.push(CheckWarning::ExternalAuthSystem("SAML2"));
    }
    if synapse_config.jwt_config.enabled {
        warnings.push(CheckWarning::ExternalAuthSystem("JWT"));
    }

    // TODO provide guidance on migrating these
    if synapse_config.password_config.enabled && !synapse_config.password_config.localdb_enabled {
        warnings.push(CheckWarning::ExternalAuthSystem(
            "non-standard password provider plugin",
        ));
    }

    if synapse_config.enable_3pid_changes {
        errors.push(CheckError::ThreepidChangesEnabled);
    }

    if synapse_config.login_via_existing_session.enabled {
        errors.push(CheckError::LoginViaExistingSessionEnabled);
    }

    (warnings, errors)
}

/// Check that the given Synapse configuration is sane for migration to a MAS with the given MAS configuration.
///
/// # Errors
///
/// - If any necessary section of MAS config cannot be parsed.
/// - If the MAS password configuration (including any necessary secrets) can't be loaded.
pub async fn synapse_config_check_against_mas_config(
    synapse: &Config,
    mas: &Figment,
) -> Result<(Vec<CheckWarning>, Vec<CheckError>), Error> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let mas_passwords = PasswordsConfig::extract_or_default(mas)?;
    let mas_password_schemes = mas_passwords
        .load()
        .await
        .map_err(Error::MasPasswordConfig)?;

    let mas_matrix = MatrixConfig::extract(mas)?;

    // Look for the MAS password hashing scheme that will be used for imported Synapse passwords,
    // then check the configuration matches so that Synapse passwords will be compatible with MAS.
    if let Some((_, algorithm, _, secret)) = mas_password_schemes
        .iter()
        .find(|(version, _, _, _)| *version == MIGRATED_PASSWORD_VERSION)
    {
        if algorithm != &PasswordAlgorithm::Bcrypt {
            errors.push(CheckError::PasswordSchemeNotBcrypt);
        }

        let synapse_pepper = synapse
            .password_config
            .pepper
            .as_ref()
            .map(String::as_bytes);
        if secret.as_deref() != synapse_pepper {
            errors.push(CheckError::PasswordSchemeWrongPepper);
        }
    } else {
        errors.push(CheckError::MissingPasswordScheme);
    }

    if synapse.allow_guest_access {
        errors.push(CheckError::GuestsEnabled);
    }

    if synapse.server_name != mas_matrix.homeserver {
        errors.push(CheckError::ServerNameMismatch {
            synapse: synapse.server_name.clone(),
            mas: mas_matrix.homeserver.clone(),
        });
    }

    let mas_captcha = CaptchaConfig::extract_or_default(mas)?;
    if synapse.enable_registration_captcha && mas_captcha.service.is_none() {
        warnings.push(CheckWarning::ShouldPortRegistrationCaptcha);
    }

    let mas_branding = BrandingConfig::extract_or_default(mas)?;
    if synapse.user_consent && mas_branding.tos_uri.is_none() {
        warnings.push(CheckWarning::ShouldPortUserConsentAsTerms);
    }

    Ok((warnings, errors))
}

/// Check that the Synapse database is sane for migration. Returns a list of warnings and errors.
///
/// # Errors
///
/// - If there is some database connection error, or the given database is not a Synapse database.
/// - If the OAuth2 section of the MAS configuration could not be parsed.
#[tracing::instrument(skip_all)]
pub async fn synapse_database_check(
    synapse_connection: &mut PgConnection,
    synapse: &Config,
    mas: &Figment,
) -> Result<(Vec<CheckWarning>, Vec<CheckError>), Error> {
    #[derive(FromRow)]
    struct UpstreamOAuthProvider {
        auth_provider: String,
        num_users: i64,
    }

    let mut errors = Vec::new();
    let warnings = Vec::new();

    let num_guests: i64 = query_scalar("SELECT COUNT(1) FROM users WHERE is_guest <> 0")
        .fetch_one(&mut *synapse_connection)
        .await?;
    if num_guests > 0 {
        errors.push(CheckError::GuestsInDatabase { num_guests });
    }

    let num_non_email_3pids: i64 =
        query_scalar("SELECT COUNT(1) FROM user_threepids WHERE medium <> 'email'")
            .fetch_one(&mut *synapse_connection)
            .await?;
    if num_non_email_3pids > 0 {
        errors.push(CheckError::NonEmailThreepidsInDatabase {
            num_non_email_3pids,
        });
    }

    let oauth_provider_user_counts = query_as::<_, UpstreamOAuthProvider>(
        "
        SELECT auth_provider, COUNT(*) AS num_users
        FROM user_external_ids
        GROUP BY auth_provider
        ORDER BY auth_provider
        ",
    )
    .fetch_all(&mut *synapse_connection)
    .await?;
    if !oauth_provider_user_counts.is_empty() {
        let syn_oauth2 = synapse.all_oidc_providers();
        let mas_oauth2 = UpstreamOAuth2Config::extract_or_default(mas)?;
        for row in oauth_provider_user_counts {
            let matching_syn = syn_oauth2.get(&row.auth_provider);

            let Some(matching_syn) = matching_syn else {
                errors.push(CheckError::SynapseMissingOAuthProvider {
                    provider: row.auth_provider,
                    num_users: row.num_users,
                });
                continue;
            };

            // Matching by `synapse_idp_id` is the same as what we'll do for the migration
            let matching_mas = mas_oauth2.providers.iter().find(|mas_provider| {
                mas_provider.synapse_idp_id.as_ref() == Some(&row.auth_provider)
            });

            if matching_mas.is_none() {
                errors.push(CheckError::MasMissingOAuthProvider {
                    provider: row.auth_provider,
                    issuer: matching_syn
                        .issuer
                        .clone()
                        .unwrap_or("<unspecified>".to_owned()),
                    num_users: row.num_users,
                });
            }
        }
    }

    Ok((warnings, errors))
}
