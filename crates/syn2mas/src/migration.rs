// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # Migration
//!
//! This module provides the high-level logic for performing the Synapse-to-MAS
//! database migration.
//!
//! This module does not implement any of the safety checks that should be run
//! *before* the migration.

use std::{pin::pin, time::Instant};

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use futures_util::StreamExt as _;
use mas_storage::Clock;
use rand::RngCore;
use thiserror::Error;
use thiserror_ext::ContextInto;
use tracing::{info, Level, Span};
use tracing_indicatif::span_ext::IndicatifSpanExt;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    mas_writer::{
        self, MasNewCompatAccessToken, MasNewCompatRefreshToken, MasNewCompatSession,
        MasNewEmailThreepid, MasNewUnsupportedThreepid, MasNewUpstreamOauthLink, MasNewUser,
        MasNewUserPassword, MasWriteBuffer, MasWriter,
    },
    progress_stream::ProgressStreamExt,
    synapse_reader::{
        self, ExtractLocalpartError, FullUserId, SynapseAccessToken, SynapseDevice,
        SynapseExternalId, SynapseRefreshableTokenPair, SynapseThreepid, SynapseUser,
    },
    HashMap, HashSet, RandomState, SynapseReader,
};

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error("error when reading synapse DB ({context}): {source}")]
    Synapse {
        source: synapse_reader::Error,
        context: String,
    },
    #[error("error when writing to MAS DB ({context}): {source}")]
    Mas {
        source: mas_writer::Error,
        context: String,
    },
    #[error("failed to extract localpart of {user:?}: {source}")]
    ExtractLocalpart {
        source: ExtractLocalpartError,
        user: FullUserId,
    },
    #[error("user {user} was not found for migration but a row in {table} was found for them")]
    MissingUserFromDependentTable { table: String, user: FullUserId },
    #[error("missing a mapping for the auth provider with ID {synapse_id:?} (used by {user} and maybe other users)")]
    MissingAuthProviderMapping {
        /// `auth_provider` ID of the provider in Synapse, for which we have no
        /// mapping
        synapse_id: String,
        /// a user that is using this auth provider
        user: FullUserId,
    },
}

struct UsersMigrated {
    /// Lookup table from user localpart to that user's UUID in MAS.
    user_localparts_to_uuid: HashMap<CompactString, Uuid>,

    /// Set of user UUIDs that correspond to Synapse admins
    synapse_admins: HashSet<Uuid>,
}

/// Performs a migration from Synapse's database to MAS' database.
///
/// # Panics
///
/// - If there are more than `usize::MAX` users
///
/// # Errors
///
/// Errors are returned under the following circumstances:
///
/// - An underlying database access error, either to MAS or to Synapse.
/// - Invalid data in the Synapse database.
#[allow(clippy::implicit_hasher)]
#[tracing::instrument(skip_all, fields(indicatif.pb_show))]
pub async fn migrate(
    mut synapse: SynapseReader<'_>,
    mut mas: MasWriter<'_>,
    server_name: &str,
    clock: &dyn Clock,
    rng: &mut impl RngCore,
    provider_id_mapping: &std::collections::HashMap<String, Uuid>,
) -> Result<(), Error> {
    let span = Span::current();
    span.pb_set_message("counting work");
    span.pb_set_length(8);
    let counts = synapse.count_rows().await.into_synapse("counting rows")?;

    span.pb_set_message("migrating user rows");
    span.pb_inc(1);
    let migrated_users = migrate_users(
        &mut synapse,
        &mut mas,
        counts
            .users
            .try_into()
            .expect("More than usize::MAX users — unable to handle this many!"),
        server_name,
        rng,
    )
    .await?;

    mas.commit().await.into_mas("committing users")?;
    mas.liberate_table("syn2mas__users")
        .await
        .into_mas("liberating users table")?;
    mas.liberate_table("syn2mas__user_passwords")
        .await
        .into_mas("liberating user_passwords table")?;

    span.pb_set_message("migrating threepids");
    span.pb_inc(1);
    migrate_threepids(
        &mut synapse,
        &mut mas,
        counts
            .threepids
            .try_into()
            .expect("More than u64::MAX threepids — unable to handle this many!"),
        server_name,
        rng,
        &migrated_users.user_localparts_to_uuid,
    )
    .await?;

    mas.commit().await.into_mas("committing threepids")?;
    mas.liberate_table("syn2mas__user_emails")
        .await
        .into_mas("liberating user_emails table")?;
    mas.liberate_table("syn2mas__user_unsupported_third_party_ids")
        .await
        .into_mas("liberating user_unsupported_third_party_ids table")?;

    span.pb_set_message("migrating user external IDs");
    span.pb_inc(1);
    migrate_external_ids(
        &mut synapse,
        &mut mas,
        counts
            .external_ids
            .try_into()
            .expect("More than u64::MAX external IDs — unable to handle this many!"),
        server_name,
        rng,
        &migrated_users.user_localparts_to_uuid,
        provider_id_mapping,
    )
    .await?;

    mas.commit().await.into_mas("committing external IDs")?;
    mas.liberate_table("syn2mas__upstream_oauth_links")
        .await
        .into_mas("liberating upstream_oauth_links table")?;

    // `(MAS user_id, device_id)` mapped to `compat_session` ULID
    let mut devices_to_compat_sessions: HashMap<(Uuid, CompactString), Uuid> =
        HashMap::with_capacity_and_hasher(
            usize::try_from(counts.devices)
                .expect("More than usize::MAX devices — unable to handle this many!")
            // Oversize the capacity, because the count is only an estimate and
            // we would like to avoid a reallocation
            * 9 / 8,
            RandomState::default(),
        );

    span.pb_set_message("migrating access tokens");
    span.pb_inc(1);
    migrate_unrefreshable_access_tokens(
        &mut synapse,
        &mut mas,
        counts
            .access_tokens
            .try_into()
            .expect("More than u64::MAX access tokens — unable to handle this many!"),
        server_name,
        clock,
        rng,
        &migrated_users.user_localparts_to_uuid,
        &mut devices_to_compat_sessions,
    )
    .await?;

    span.pb_set_message("migrating refresh tokens");
    span.pb_inc(1);
    migrate_refreshable_token_pairs(
        &mut synapse,
        &mut mas,
        counts
            .refresh_tokens
            .try_into()
            .expect("More than u64::MAX refresh tokens — unable to handle this many!"),
        server_name,
        clock,
        rng,
        &migrated_users.user_localparts_to_uuid,
        &mut devices_to_compat_sessions,
    )
    .await?;

    mas.commit().await.into_mas("committing tokens")?;
    mas.liberate_table("syn2mas__compat_access_tokens")
        .await
        .into_mas("liberating compat_access_tokens table")?;
    mas.liberate_table("syn2mas__compat_refresh_tokens")
        .await
        .into_mas("liberating compat_refresh_tokens table")?;

    span.pb_set_message("migrating devices");
    span.pb_inc(1);
    migrate_devices(
        &mut synapse,
        &mut mas,
        counts
            .devices
            .try_into()
            .expect("More than u64::MAX devices — unable to handle this many!"),
        server_name,
        rng,
        &migrated_users.user_localparts_to_uuid,
        &mut devices_to_compat_sessions,
        &migrated_users.synapse_admins,
    )
    .await?;

    mas.commit().await.into_mas("committing devices")?;
    mas.liberate_table("syn2mas__compat_sessions")
        .await
        .into_mas("liberating compat_sessions table")?;

    span.pb_set_message("closing Synapse database");
    span.pb_inc(1);
    synapse
        .finish()
        .await
        .into_synapse("failed to close Synapse reader")?;

    span.pb_inc(1);
    span.pb_set_message("finalising MAS database");
    mas.finish()
        .await
        .into_mas("failed to finalise MAS database")?;

    span.pb_set_message("migrated!");
    span.pb_inc(1);

    Ok(())
}

#[tracing::instrument(skip_all, fields(indicatif.pb_show), level = Level::INFO)]
async fn migrate_users(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    user_count_hint: usize,
    server_name: &str,
    rng: &mut impl RngCore,
) -> Result<UsersMigrated, Error> {
    let start = Instant::now();

    let mut user_buffer = MasWriteBuffer::new(mas, MasWriter::write_users);
    let mut password_buffer = MasWriteBuffer::new(mas, MasWriter::write_passwords);
    let mut users_stream = pin!(synapse
        .read_users()
        .with_progress_bar(user_count_hint as u64, 10_000));
    // Oversize the capacity, because the count is only an estimate and
    // we would like to avoid a reallocation
    let mut user_localparts_to_uuid =
        HashMap::with_capacity_and_hasher(user_count_hint * 9 / 8, RandomState::default());
    let mut synapse_admins = HashSet::with_hasher(RandomState::default());

    while let Some(user_res) = users_stream.next().await {
        let user = user_res.into_synapse("reading user")?;
        let (mas_user, mas_password_opt) = transform_user(&user, server_name, rng)?;

        if bool::from(user.admin) {
            // Note down the fact that this user is a Synapse admin,
            // because we will grant their existing devices the Synapse admin
            // flag
            synapse_admins.insert(mas_user.user_id);
        }

        user_localparts_to_uuid.insert(CompactString::new(&mas_user.username), mas_user.user_id);

        user_buffer
            .write(mas, mas_user)
            .await
            .into_mas("writing user")?;

        if let Some(mas_password) = mas_password_opt {
            password_buffer
                .write(mas, mas_password)
                .await
                .into_mas("writing password")?;
        }
    }

    user_buffer.finish(mas).await.into_mas("writing users")?;

    password_buffer
        .finish(mas)
        .await
        .into_mas("writing passwords")?;

    info!(
        "users migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok(UsersMigrated {
        user_localparts_to_uuid,
        synapse_admins,
    })
}

#[tracing::instrument(skip_all, fields(indicatif.pb_show), level = Level::INFO)]
async fn migrate_threepids(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    count_hint: u64,
    server_name: &str,
    rng: &mut impl RngCore,
    user_localparts_to_uuid: &HashMap<CompactString, Uuid>,
) -> Result<(), Error> {
    let start = Instant::now();

    let mut email_buffer = MasWriteBuffer::new(mas, MasWriter::write_email_threepids);
    let mut unsupported_buffer = MasWriteBuffer::new(mas, MasWriter::write_unsupported_threepids);
    let mut users_stream = pin!(synapse
        .read_threepids()
        .with_progress_bar(count_hint, 10_000));

    while let Some(threepid_res) = users_stream.next().await {
        let SynapseThreepid {
            user_id: synapse_user_id,
            medium,
            address,
            added_at,
        } = threepid_res.into_synapse("reading threepid")?;
        let created_at: DateTime<Utc> = added_at.into();

        let Ok(username) = synapse_user_id
            .extract_localpart(server_name)
            .into_extract_localpart(synapse_user_id.clone())
            .map(str::to_owned)
        else {
            // HACK matrix.org
            continue;
        };
        let Some(user_id) = user_localparts_to_uuid.get(username.as_str()).copied() else {
            if true || is_likely_appservice(&username) {
                // HACK can we do anything better
                continue;
            }
            return Err(Error::MissingUserFromDependentTable {
                table: "user_threepids".to_owned(),
                user: synapse_user_id,
            });
        };

        if medium == "email" {
            email_buffer
                .write(
                    mas,
                    MasNewEmailThreepid {
                        user_id,
                        user_email_id: Uuid::from(Ulid::from_datetime_with_source(
                            created_at.into(),
                            rng,
                        )),
                        email: address,
                        created_at,
                    },
                )
                .await
                .into_mas("writing email")?;
        } else {
            unsupported_buffer
                .write(
                    mas,
                    MasNewUnsupportedThreepid {
                        user_id,
                        medium,
                        address,
                        created_at,
                    },
                )
                .await
                .into_mas("writing unsupported threepid")?;
        }
    }

    email_buffer
        .finish(mas)
        .await
        .into_mas("writing email threepids")?;
    unsupported_buffer
        .finish(mas)
        .await
        .into_mas("writing unsupported threepids")?;

    info!(
        "third-party IDs migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok(())
}

/// # Parameters
///
/// - `provider_id_mapping`: mapping from Synapse `auth_provider` ID to UUID of
///   the upstream provider in MAS.
#[tracing::instrument(skip_all, fields(indicatif.pb_show), level = Level::INFO)]
async fn migrate_external_ids(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    count_hint: u64,
    server_name: &str,
    rng: &mut impl RngCore,
    user_localparts_to_uuid: &HashMap<CompactString, Uuid>,
    provider_id_mapping: &std::collections::HashMap<String, Uuid>,
) -> Result<(), Error> {
    let start = Instant::now();

    let mut write_buffer = MasWriteBuffer::new(mas, MasWriter::write_upstream_oauth_links);
    let mut extids_stream = pin!(synapse
        .read_user_external_ids()
        .with_progress_bar(count_hint, 10_000));

    while let Some(extid_res) = extids_stream.next().await {
        let SynapseExternalId {
            user_id: synapse_user_id,
            auth_provider,
            external_id: subject,
        } = extid_res.into_synapse("reading external ID")?;
        let username = synapse_user_id
            .extract_localpart(server_name)
            .into_extract_localpart(synapse_user_id.clone())?
            .to_owned();
        let Some(user_id) = user_localparts_to_uuid.get(username.as_str()).copied() else {
            if true || is_likely_appservice(&username) {
                // HACK can we do anything better
                continue;
            }
            return Err(Error::MissingUserFromDependentTable {
                table: "user_external_ids".to_owned(),
                user: synapse_user_id,
            });
        };

        let Some(&upstream_provider_id) = provider_id_mapping.get(&auth_provider) else {
            return Err(Error::MissingAuthProviderMapping {
                synapse_id: auth_provider,
                user: synapse_user_id,
            });
        };

        // To save having to store user creation times, extract it from the ULID
        // This gives millisecond precision — good enough.
        let user_created_ts = Ulid::from(user_id).datetime();

        let link_id: Uuid = Ulid::from_datetime_with_source(user_created_ts, rng).into();

        write_buffer
            .write(
                mas,
                MasNewUpstreamOauthLink {
                    link_id,
                    user_id,
                    upstream_provider_id,
                    subject,
                    created_at: user_created_ts.into(),
                },
            )
            .await
            .into_mas("failed to write upstream link")?;
    }

    write_buffer
        .finish(mas)
        .await
        .into_mas("writing upstream links")?;

    info!(
        "upstream links (external IDs) migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok(())
}

/// Migrate devices from Synapse to MAS (as compat sessions).
///
/// In order to get the right session creation timestamps, the access tokens
/// must counterintuitively be migrated first, with the ULIDs passed in as
/// `devices`.
///
/// This is because only access tokens store a timestamp that in any way
/// resembles a creation timestamp.
#[tracing::instrument(skip_all, fields(indicatif.pb_show), level = Level::INFO)]
#[allow(clippy::too_many_arguments)]
async fn migrate_devices(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    count_hint: u64,
    server_name: &str,
    rng: &mut impl RngCore,
    user_localparts_to_uuid: &HashMap<CompactString, Uuid>,
    devices: &mut HashMap<(Uuid, CompactString), Uuid>,
    synapse_admins: &HashSet<Uuid>,
) -> Result<(), Error> {
    let start = Instant::now();

    let mut devices_stream = pin!(synapse.read_devices().with_progress_bar(count_hint, 10_000));
    let mut write_buffer = MasWriteBuffer::new(mas, MasWriter::write_compat_sessions);

    while let Some(device_res) = devices_stream.next().await {
        let SynapseDevice {
            user_id: synapse_user_id,
            device_id,
            display_name,
            last_seen,
            ip,
            user_agent,
        } = device_res.into_synapse("reading Synapse device")?;

        let username = synapse_user_id
            .extract_localpart(server_name)
            .into_extract_localpart(synapse_user_id.clone())?
            .to_owned();
        let Some(user_id) = user_localparts_to_uuid.get(username.as_str()).copied() else {
            if true || is_likely_appservice(&username) {
                // HACK can we do anything better
                continue;
            }
            return Err(Error::MissingUserFromDependentTable {
                table: "devices".to_owned(),
                user: synapse_user_id,
            });
        };

        let session_id = *devices
            .entry((user_id, CompactString::new(&device_id)))
            .or_insert_with(||
                // We don't have a creation time for this device (as it has no access token),
                // so use now as a least-evil fallback.
                Ulid::with_source(rng).into());
        let created_at = Ulid::from(session_id).datetime().into();

        // TODO skip access tokens for deactivated users
        write_buffer
            .write(
                mas,
                MasNewCompatSession {
                    session_id,
                    user_id,
                    device_id: Some(device_id),
                    human_name: display_name,
                    created_at,
                    is_synapse_admin: synapse_admins.contains(&user_id),
                    last_active_at: last_seen.map(DateTime::from),
                    last_active_ip: ip.map(|ip| ip.parse()).transpose().ok().flatten(),
                    user_agent,
                },
            )
            .await
            .into_mas("writing compat sessions")?;
    }

    write_buffer
        .finish(mas)
        .await
        .into_mas("writing compat sessions")?;

    info!(
        "devices migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok(())
}

/// Migrates unrefreshable access tokens (those without an associated refresh
/// token). Some of these may be deviceless.
#[tracing::instrument(skip_all, fields(indicatif.pb_show), level = Level::INFO)]
#[allow(clippy::too_many_arguments)]
async fn migrate_unrefreshable_access_tokens(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    count_hint: u64,
    server_name: &str,
    clock: &dyn Clock,
    rng: &mut impl RngCore,
    user_localparts_to_uuid: &HashMap<CompactString, Uuid>,
    devices: &mut HashMap<(Uuid, CompactString), Uuid>,
) -> Result<(), Error> {
    let start = Instant::now();

    let mut token_stream = pin!(synapse
        .read_unrefreshable_access_tokens()
        .with_progress_bar(count_hint, 10_000));
    let mut write_buffer = MasWriteBuffer::new(mas, MasWriter::write_compat_access_tokens);
    let mut deviceless_session_write_buffer =
        MasWriteBuffer::new(mas, MasWriter::write_compat_sessions);

    while let Some(token_res) = token_stream.next().await {
        let SynapseAccessToken {
            user_id: synapse_user_id,
            device_id,
            token,
            valid_until_ms,
            last_validated,
        } = token_res.into_synapse("reading Synapse access token")?;

        let username = synapse_user_id
            .extract_localpart(server_name)
            .into_extract_localpart(synapse_user_id.clone())?
            .to_owned();
        let Some(user_id) = user_localparts_to_uuid.get(username.as_str()).copied() else {
            if true || is_likely_appservice(&username) {
                // HACK can we do anything better
                continue;
            }
            return Err(Error::MissingUserFromDependentTable {
                table: "access_tokens".to_owned(),
                user: synapse_user_id,
            });
        };

        // It's not always accurate, but last_validated is *often* the creation time of
        // the device If we don't have one, then use the current time as a
        // fallback.
        let created_at = last_validated.map_or_else(|| clock.now(), DateTime::from);

        let session_id = if let Some(device_id) = device_id {
            // Use the existing device_id if this is the second token for a device
            *devices
                .entry((user_id, CompactString::new(&device_id)))
                .or_insert_with(|| {
                    Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng))
                })
        } else {
            // If this is a deviceless access token, create a deviceless compat session
            // for it (since otherwise we won't create one whilst migrating devices)
            let deviceless_session_id =
                Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng));

            deviceless_session_write_buffer
                .write(
                    mas,
                    MasNewCompatSession {
                        session_id: deviceless_session_id,
                        user_id,
                        device_id: None,
                        human_name: None,
                        created_at,
                        is_synapse_admin: false,
                        last_active_at: None,
                        last_active_ip: None,
                        user_agent: None,
                    },
                )
                .await
                .into_mas("failed to write deviceless compat sessions")?;

            deviceless_session_id
        };

        let token_id = Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng));

        // TODO skip access tokens for deactivated users
        write_buffer
            .write(
                mas,
                MasNewCompatAccessToken {
                    token_id,
                    session_id,
                    access_token: token,
                    created_at,
                    expires_at: valid_until_ms.map(DateTime::from),
                },
            )
            .await
            .into_mas("writing compat access tokens")?;
    }

    write_buffer
        .finish(mas)
        .await
        .into_mas("writing compat access tokens")?;
    deviceless_session_write_buffer
        .finish(mas)
        .await
        .into_mas("writing deviceless compat sessions")?;

    info!(
        "non-refreshable access tokens migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok(())
}

/// Migrates (access token, refresh token) pairs.
/// Does not migrate non-refreshable access tokens.
#[tracing::instrument(skip_all, fields(indicatif.pb_show), level = Level::INFO)]
#[allow(clippy::too_many_arguments)]
async fn migrate_refreshable_token_pairs(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    count_hint: u64,
    server_name: &str,
    clock: &dyn Clock,
    rng: &mut impl RngCore,
    user_localparts_to_uuid: &HashMap<CompactString, Uuid>,
    devices: &mut HashMap<(Uuid, CompactString), Uuid>,
) -> Result<(), Error> {
    let start = Instant::now();

    let mut token_stream = pin!(synapse
        .read_refreshable_token_pairs()
        .with_progress_bar(count_hint, 10_000));
    let mut access_token_write_buffer =
        MasWriteBuffer::new(mas, MasWriter::write_compat_access_tokens);
    let mut refresh_token_write_buffer =
        MasWriteBuffer::new(mas, MasWriter::write_compat_refresh_tokens);

    while let Some(token_res) = token_stream.next().await {
        let SynapseRefreshableTokenPair {
            user_id: synapse_user_id,
            device_id,
            access_token,
            refresh_token,
            valid_until_ms,
            last_validated,
        } = token_res.into_synapse("reading Synapse refresh token")?;

        let username = synapse_user_id
            .extract_localpart(server_name)
            .into_extract_localpart(synapse_user_id.clone())?
            .to_owned();
        let Some(user_id) = user_localparts_to_uuid.get(username.as_str()).copied() else {
            if true || is_likely_appservice(&username) {
                // HACK can we do anything better
                continue;
            }
            return Err(Error::MissingUserFromDependentTable {
                table: "refresh_tokens".to_owned(),
                user: synapse_user_id,
            });
        };

        // It's not always accurate, but last_validated is *often* the creation time of
        // the device If we don't have one, then use the current time as a
        // fallback.
        let created_at = last_validated.map_or_else(|| clock.now(), DateTime::from);

        // Use the existing device_id if this is the second token for a device
        let session_id = *devices
            .entry((user_id, CompactString::new(&device_id)))
            .or_insert_with(|| Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng)));

        let access_token_id = Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng));
        let refresh_token_id = Uuid::from(Ulid::from_datetime_with_source(created_at.into(), rng));

        // TODO skip access tokens for deactivated users
        access_token_write_buffer
            .write(
                mas,
                MasNewCompatAccessToken {
                    token_id: access_token_id,
                    session_id,
                    access_token,
                    created_at,
                    expires_at: valid_until_ms.map(DateTime::from),
                },
            )
            .await
            .into_mas("writing compat access tokens")?;
        refresh_token_write_buffer
            .write(
                mas,
                MasNewCompatRefreshToken {
                    refresh_token_id,
                    session_id,
                    access_token_id,
                    refresh_token,
                    created_at,
                },
            )
            .await
            .into_mas("writing compat refresh tokens")?;
    }

    access_token_write_buffer
        .finish(mas)
        .await
        .into_mas("writing compat access tokens")?;

    refresh_token_write_buffer
        .finish(mas)
        .await
        .into_mas("writing compat refresh tokens")?;

    info!(
        "refreshable token pairs migrated in {:.1}s",
        Instant::now().duration_since(start).as_secs_f64()
    );

    Ok(())
}

fn transform_user(
    user: &SynapseUser,
    server_name: &str,
    rng: &mut impl RngCore,
) -> Result<(MasNewUser, Option<MasNewUserPassword>), Error> {
    let username = user
        .name
        .extract_localpart(server_name)
        .into_extract_localpart(user.name.clone())?
        .to_owned();

    let new_user = MasNewUser {
        user_id: Uuid::from(Ulid::from_datetime_with_source(
            DateTime::<Utc>::from(user.creation_ts).into(),
            rng,
        )),
        username,
        created_at: user.creation_ts.into(),
        locked_at: bool::from(user.deactivated).then_some(user.creation_ts.into()),
        can_request_admin: bool::from(user.admin),
        is_guest: bool::from(user.is_guest),
    };

    let mas_password = user
        .password_hash
        .clone()
        .map(|password_hash| MasNewUserPassword {
            user_password_id: Uuid::from(Ulid::from_datetime_with_source(
                DateTime::<Utc>::from(user.creation_ts).into(),
                rng,
            )),
            user_id: new_user.user_id,
            hashed_password: password_hash,
            created_at: new_user.created_at,
        });

    Ok((new_user, mas_password))
}

/// Returns true if and only if the given localpart looks like it would belong
/// to an application service user.
/// The rule here is that it must start with an underscore.
/// Synapse reserves these by default, but there is no hard rule prohibiting
/// other namespaces from being reserved, so this is not a robust check.
// TODO replace with a more robust mechanism, if we even care about this sanity check
// e.g. read application service registration files.
#[inline]
fn is_likely_appservice(localpart: &str) -> bool {
    localpart.starts_with('_')
}
