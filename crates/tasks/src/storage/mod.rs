// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Reimplementation of the [`apalis_sql::storage::PostgresStorage`] using a
//! shared connection for the [`PgListener`]

mod from_row;
mod postgres;

use self::from_row::SqlJobRequest;
pub(crate) use self::postgres::StorageFactory as PostgresStorageFactory;
