// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::fmt::Display;

use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;

/// Encountered when trying to register a user ID which has been taken.
/// — <https://spec.matrix.org/v1.10/client-server-api/#other-error-codes>
pub(crate) const M_USER_IN_USE: &str = "M_USER_IN_USE";
/// Encountered when trying to register a user ID which is not valid.
/// — <https://spec.matrix.org/v1.10/client-server-api/#other-error-codes>
pub(crate) const M_INVALID_USERNAME: &str = "M_INVALID_USERNAME";
/// Encountered when trying to register a user ID reserved by an appservice.
/// — <https://spec.matrix.org/v1.10/client-server-api/#other-error-codes>
pub(crate) const M_EXCLUSIVE: &str = "M_EXCLUSIVE";

/// Represents a Matrix error
/// Ref: <https://spec.matrix.org/v1.10/client-server-api/#standard-error-response>
#[derive(Debug, Deserialize)]
struct MatrixError {
    errcode: String,
    error: String,
}

/// Represents an error received from the homeserver.
/// Where possible, we capture the Matrix error from the JSON response body.
#[derive(Debug, Error)]
pub(crate) struct Error {
    synapse_error: Option<MatrixError>,

    #[source]
    source: reqwest::Error,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(matrix_error) = &self.synapse_error {
            write!(f, "{}: {}", matrix_error.errcode, matrix_error.error)
        } else {
            write!(f, "(no specific error)")
        }
    }
}

impl Error {
    /// Return the error code (`errcode`)
    pub fn errcode(&self) -> Option<&str> {
        let me = self.synapse_error.as_ref()?;
        Some(&me.errcode)
    }
}

/// An extension trait for [`reqwest::Response`] to help working with errors
/// from Synapse.
#[async_trait]
pub(crate) trait SynapseResponseExt: Sized {
    async fn error_for_synapse_error(self) -> Result<Self, Error>;
}

#[async_trait]
impl SynapseResponseExt for reqwest::Response {
    async fn error_for_synapse_error(self) -> Result<Self, Error> {
        match self.error_for_status_ref() {
            Ok(_response) => Ok(self),
            Err(source) => {
                let synapse_error = self.json().await.ok();
                Err(Error {
                    synapse_error,
                    source,
                })
            }
        }
    }
}
