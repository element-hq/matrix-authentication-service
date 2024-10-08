//! # Migration
//!
//! This module provides the high-level logic for performing the Synapse-to-MAS database migration.
//!
//! This module does not implement any of the safety checks that should be run *before* the migration.

use std::{
    collections::{BTreeMap, HashMap},
    pin::pin,
};

use compact_str::CompactString;
use futures_util::StreamExt;
use rand::rngs::ThreadRng;
use thiserror::Error;
use thiserror_ext::ContextInto;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    mas_writer::{self, MasNewUser, MasWriteBuffer, MasWriter},
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
    // TODO compact string optimisation
    user_localparts_to_uuid: HashMap<CompactString, Uuid>,
}

pub async fn migrate(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    server_name: &str,
    rng: &mut ThreadRng,
) -> Result<(), Error> {
    let counts = synapse.count_rows().await.into_synapse("counting users")?;

    let mut write_buf = MasWriteBuffer::default();

    migrate_users(
        synapse,
        mas,
        &mut write_buf,
        counts
            .users
            .try_into()
            .expect("More than usize::MAX users — wow!"),
        server_name,
        rng,
    )
    .await?;

    write_buf.finish(mas).await.into_mas("flush")?;

    Ok(())
}

async fn migrate_users(
    synapse: &mut SynapseReader<'_>,
    mas: &mut MasWriter<'_>,
    write_buffer: &mut MasWriteBuffer,
    user_count_hint: usize,
    server_name: &str,
    rng: &mut ThreadRng,
) -> Result<UsersMigrated, Error> {
    let mut users_stream = pin!(synapse.read_users());
    // TODO is 1:1 capacity enough for a hashmap?
    let mut user_localparts_to_uuid = HashMap::with_capacity(user_count_hint);

    while let Some(user_res) = users_stream.next().await {
        let user = user_res.into_synapse("reading user")?;
        let (mas_user, mas_password_opt) = transform_user(&user, server_name, rng)?;

        user_localparts_to_uuid.insert(CompactString::new(&mas_user.username), mas_user.user_id);

        write_buffer
            .write_user(mas, mas_user)
            .await
            .into_mas("writing user")?;

        if let Some(mas_password) = mas_password_opt {
            todo!()
        }
    }

    write_buffer
        .flush_users(mas)
        .await
        .into_mas("writing users")?;

    Ok(UsersMigrated {
        user_localparts_to_uuid,
    })
}

fn transform_user(
    user: &SynapseUser,
    server_name: &str,
    rng: &mut ThreadRng,
) -> Result<(MasNewUser, Option<()>), Error> {
    let username = user
        .name
        .extract_localpart(server_name)
        .into_extract_localpart(user.name.clone())?
        .to_owned();

    let new_user = MasNewUser {
        user_id: Uuid::from(Ulid::from_datetime_with_source(
            user.creation_ts.0.into(),
            rng,
        )),
        username,
        created_at: user.creation_ts.0,
        locked_at: user.deactivated.0.then_some(user.creation_ts.0),
        can_request_admin: user.admin.0,
    };

    // TODO password support
    Ok((new_user, None))
}
