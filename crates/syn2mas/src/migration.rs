// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # Migration
//!
//! This module provides the high-level logic for performing the Synapse-to-MAS database migration.
//!
//! This module does not implement any of the safety checks that should be run *before* the migration.

use std::{collections::HashMap, pin::pin};

use chrono::{DateTime, Utc};
use compact_str::CompactString;
use futures_util::StreamExt as _;
use rand::RngCore;
use thiserror::Error;
use thiserror_ext::ContextInto;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    mas_writer::{self, MasNewUser, MasNewUserPassword, MasUserWriteBuffer, MasWriter},
    synapse_reader::{self, ExtractLocalpartError, FullUserId, SynapseUser},
    SynapseReader,
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
}

struct UsersMigrated {
    /// Lookup table from user localpart to that user's UUID in MAS.
    user_localparts_to_uuid: HashMap<CompactString, Uuid>,
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
pub async fn migrate(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    server_name: &str,
    rng: &mut impl RngCore,
) -> Result<(), Error> {
    let counts = synapse.count_rows().await.into_synapse("counting users")?;

    migrate_users(
        synapse,
        mas,
        counts
            .users
            .try_into()
            .expect("More than usize::MAX users — wow!"),
        server_name,
        rng,
    )
    .await?;

    Ok(())
}

async fn migrate_users(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    user_count_hint: usize,
    server_name: &str,
    rng: &mut impl RngCore,
) -> Result<UsersMigrated, Error> {
    let mut write_buffer = MasUserWriteBuffer::new(mas);
    let mut users_stream = pin!(synapse.read_users());
    // TODO is 1:1 capacity enough for a hashmap?
    let mut user_localparts_to_uuid = HashMap::with_capacity(user_count_hint);

    while let Some(user_res) = users_stream.next().await {
        let user = user_res.into_synapse("reading user")?;
        let (mas_user, mas_password_opt) = transform_user(&user, server_name, rng)?;

        user_localparts_to_uuid.insert(CompactString::new(&mas_user.username), mas_user.user_id);

        write_buffer
            .write_user(mas_user)
            .await
            .into_mas("writing user")?;

        if let Some(mas_password) = mas_password_opt {
            write_buffer
                .write_password(mas_password)
                .await
                .into_mas("writing password")?;
        }
    }

    write_buffer
        .finish()
        .await
        .into_mas("writing users & passwords")?;

    Ok(UsersMigrated {
        user_localparts_to_uuid,
    })
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
