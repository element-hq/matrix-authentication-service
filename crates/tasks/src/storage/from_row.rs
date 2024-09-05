// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::str::FromStr;

use apalis_core::{context::JobContext, job::JobId, request::JobRequest, worker::WorkerId};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Row;

/// Wrapper for [`JobRequest`]
pub(crate) struct SqlJobRequest<T>(JobRequest<T>);

impl<T> From<SqlJobRequest<T>> for JobRequest<T> {
    fn from(val: SqlJobRequest<T>) -> Self {
        val.0
    }
}

impl<'r, T: serde::de::DeserializeOwned> sqlx::FromRow<'r, sqlx::postgres::PgRow>
    for SqlJobRequest<T>
{
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let job: Value = row.try_get("job")?;
        let id: JobId =
            JobId::from_str(row.try_get("id")?).map_err(|e| sqlx::Error::ColumnDecode {
                index: "id".to_owned(),
                source: Box::new(e),
            })?;
        let mut context = JobContext::new(id);

        let run_at = row.try_get("run_at")?;
        context.set_run_at(run_at);

        let attempts = row.try_get("attempts").unwrap_or(0);
        context.set_attempts(attempts);

        let max_attempts = row.try_get("max_attempts").unwrap_or(25);
        context.set_max_attempts(max_attempts);

        let done_at: Option<DateTime<Utc>> = row.try_get("done_at").unwrap_or_default();
        context.set_done_at(done_at);

        let lock_at: Option<DateTime<Utc>> = row.try_get("lock_at").unwrap_or_default();
        context.set_lock_at(lock_at);

        let last_error = row.try_get("last_error").unwrap_or_default();
        context.set_last_error(last_error);

        let status: String = row.try_get("status")?;
        context.set_status(status.parse().map_err(|e| sqlx::Error::ColumnDecode {
            index: "job".to_owned(),
            source: Box::new(e),
        })?);

        let lock_by: Option<String> = row.try_get("lock_by").unwrap_or_default();
        context.set_lock_by(lock_by.map(WorkerId::new));

        Ok(SqlJobRequest(JobRequest::new_with_context(
            serde_json::from_value(job).map_err(|e| sqlx::Error::ColumnDecode {
                index: "job".to_owned(),
                source: Box::new(e),
            })?,
            context,
        )))
    }
}
