// Copyright 2024 New Vector Ltd.
// Copyright 2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Methods related to the account management URL.
//!
//! This is a Matrix extension introduced in [MSC2965](https://github.com/matrix-org/matrix-spec-proposals/pull/2965).

use serde::Serialize;
use serde_with::skip_serializing_none;
use url::Url;

use crate::error::AccountManagementError;

/// An account management action that a user can take, including a device ID for
/// the actions that support it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action")]
#[non_exhaustive]
pub enum AccountManagementActionFull {
    /// `org.matrix.profile`
    ///
    /// The user wishes to view their profile (name, avatar, contact details).
    #[serde(rename = "org.matrix.profile")]
    Profile,

    /// `org.matrix.sessions_list`
    ///
    /// The user wishes to view a list of their sessions.
    #[serde(rename = "org.matrix.sessions_list")]
    SessionsList,

    /// `org.matrix.session_view`
    ///
    /// The user wishes to view the details of a specific session.
    #[serde(rename = "org.matrix.session_view")]
    SessionView {
        /// The ID of the session to view the details of.
        device_id: String,
    },

    /// `org.matrix.session_end`
    ///
    /// The user wishes to end/log out of a specific session.
    #[serde(rename = "org.matrix.session_end")]
    SessionEnd {
        /// The ID of the session to end.
        device_id: String,
    },

    /// `org.matrix.account_deactivate`
    ///
    /// The user wishes to deactivate their account.
    #[serde(rename = "org.matrix.account_deactivate")]
    AccountDeactivate,

    /// `org.matrix.cross_signing_reset`
    ///
    /// The user wishes to reset their cross-signing keys.
    #[serde(rename = "org.matrix.cross_signing_reset")]
    CrossSigningReset,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize)]
struct AccountManagementData {
    #[serde(flatten)]
    action: Option<AccountManagementActionFull>,
    id_token_hint: Option<String>,
}

/// Build the URL for accessing the account management capabilities.
///
/// # Arguments
///
/// * `account_management_uri` - The URL to access the issuer's account
///   management capabilities.
///
/// * `action` - The action that the user wishes to take.
///
/// * `id_token_hint` - An ID Token that was previously issued to the client,
///   used as a hint for which user is requesting to manage their account.
///
/// # Returns
///
/// A URL to be opened in a web browser where the end-user will be able to
/// access the account management capabilities of the issuer.
///
/// # Errors
///
/// Returns an error if serializing the URL fails.
pub fn build_account_management_url(
    mut account_management_uri: Url,
    action: Option<AccountManagementActionFull>,
    id_token_hint: Option<String>,
) -> Result<Url, AccountManagementError> {
    let data = AccountManagementData {
        action,
        id_token_hint,
    };
    let extra_query = serde_urlencoded::to_string(data)?;

    if !extra_query.is_empty() {
        // Add our parameters to the query, because the URL might already have one.
        let mut full_query = account_management_uri
            .query()
            .map(ToOwned::to_owned)
            .unwrap_or_default();

        if !full_query.is_empty() {
            full_query.push('&');
        }
        full_query.push_str(&extra_query);

        account_management_uri.set_query(Some(&full_query));
    }

    Ok(account_management_uri)
}
