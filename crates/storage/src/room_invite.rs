// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Inviting people to a room by email

use std::collections::HashSet;

use chrono::Duration;
use mas_data_model::Clock;
use rand::{
    RngCore,
    distributions::{Alphanumeric, DistString},
};

use crate::{
    RepositoryAccess,
    queue::{QueueJobRepositoryExt as _, SendRoomInviteEmailJob},
};

/// How much to space out the individual sends, so that a large batch doesn't
/// burst against the SMTP server. 100ms gives a ceiling of ~10 emails/second.
const SEND_INTERVAL: Duration = Duration::milliseconds(100);

/// Length of a generated invite token, in alphanumeric characters
const TOKEN_LENGTH: usize = 12;

/// Someone to invite to a room
pub struct RoomInvite {
    /// The address to invite, which the recipient is pinned to
    pub email: String,

    /// The localpart to impose on the recipient, if any
    pub username: Option<String>,
}

/// Mint a registration token for each recipient and schedule the invite emails.
///
/// The tokens are single-use and passwordless: the recipient is identified by
/// the address they were invited at, which the token pins, so there is nothing
/// left for them to choose that could point the invite somewhere else.
///
/// Repeated addresses are invited once. Neither the tokens nor the jobs are
/// visible until the caller commits, so a batch either goes out whole or not
/// at all.
///
/// Returns how many recipients were scheduled.
///
/// # Parameters
///
/// * `repo` - The repository to mint the tokens and schedule the jobs in
/// * `rng` - The random number generator used to generate the tokens
/// * `clock` - The clock used to generate timestamps
/// * `room_id` - The room to invite the recipients to
/// * `invites` - The recipients to invite
///
/// # Errors
///
/// Returns an error if the underlying repository fails.
pub async fn schedule_room_invites<R: RepositoryAccess + ?Sized>(
    repo: &mut R,
    rng: &mut (dyn RngCore + Send),
    clock: &dyn Clock,
    room_id: &str,
    invites: impl IntoIterator<Item = RoomInvite> + Send,
) -> Result<usize, R::Error> {
    let now = clock.now();
    let mut seen = HashSet::new();
    let mut delay = Duration::zero();

    for invite in invites {
        if !seen.insert(invite.email.clone()) {
            continue;
        }

        let token = Alphanumeric.sample_string(rng, TOKEN_LENGTH);
        let token = repo
            .user_registration_token()
            .add(
                rng,
                clock,
                token,
                Some(1),
                None,
                invite.username,
                Some(invite.email),
                true,
            )
            .await?;

        // One job per recipient, so that a bad address or a transient SMTP
        // failure retries that single email rather than the whole batch.
        repo.queue_job()
            .schedule_job_later(
                rng,
                clock,
                SendRoomInviteEmailJob::new(room_id, token.id),
                now + delay,
            )
            .await?;

        delay += SEND_INTERVAL;
    }

    Ok(seen.len())
}
