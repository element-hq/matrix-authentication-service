// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Requests for [RP-Initiated Logout].
//!
//! [RP-Initiated Logout]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

use language_tags::LanguageTag;
use oauth2_types::oidc::RpInitiatedLogoutRequest;
use rand::{
    distributions::{Alphanumeric, DistString},
    Rng,
};
use url::Url;

/// The data necessary to build a logout request.
#[derive(Default, Clone)]
pub struct LogoutData {
    /// ID Token previously issued by the OP to the RP.
    ///
    /// Recommended, used as a hint about the End-User's current authenticated
    /// session with the Client.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the End-User that is logging out.
    ///
    /// The value and meaning of this parameter is left up to the OP's
    /// discretion. For instance, the value might contain an email address,
    /// phone number, username, or session identifier pertaining to the RP's
    /// session with the OP for the End-User.
    pub logout_hint: Option<String>,

    /// OAuth 2.0 Client Identifier valid at the Authorization Server.
    ///
    /// The most common use case for this parameter is to specify the Client
    /// Identifier when `post_logout_redirect_uri` is used but `id_token_hint`
    /// is not. Another use is for symmetrically encrypted ID Tokens used as
    /// `id_token_hint` values that require the Client Identifier to be
    /// specified by other means, so that the ID Tokens can be decrypted by
    /// the OP.
    pub client_id: Option<String>,

    /// URI to which the RP is requesting that the End-User's User Agent be
    /// redirected after a logout has been performed.
    ///
    /// The value MUST have been previously registered with the OP, using the
    /// `post_logout_redirect_uris` registration parameter.
    pub post_logout_redirect_uri: Option<Url>,

    /// The End-User's preferred languages and scripts for the user interface,
    /// ordered by preference.
    pub ui_locales: Option<Vec<LanguageTag>>,
}

/// Build the URL for initiating logout at the logout endpoint.
///
/// # Arguments
///
/// * `end_session_endpoint` - The URL of the issuer's logout endpoint.
///
/// * `logout_data` - The data necessary to build the logout request.
///
/// * `rng` - A random number generator.
///
/// # Returns
///
/// A URL to be opened in a web browser where the end-user will be able to
/// logout of their session, and an optional `state` string.
///
/// The `state` will only be set if `post_logout_redirect_uri` is set. It should
/// be present in the query when the end user is redirected to the
/// `post_logout_redirect_uri`.
///
/// # Errors
///
/// Returns an error if preparing the URL fails.
///
/// [`VerifiedClientMetadata`]: oauth2_types::registration::VerifiedClientMetadata
/// [`ClientErrorCode`]: oauth2_types::errors::ClientErrorCode
pub fn build_end_session_url(
    mut end_session_endpoint: Url,
    logout_data: LogoutData,
    rng: &mut impl Rng,
) -> Result<(Url, Option<String>), serde_urlencoded::ser::Error> {
    let LogoutData {
        id_token_hint,
        logout_hint,
        client_id,
        post_logout_redirect_uri,
        ui_locales,
    } = logout_data;

    let state = if post_logout_redirect_uri.is_some() {
        Some(Alphanumeric.sample_string(rng, 16))
    } else {
        None
    };

    let logout_request = RpInitiatedLogoutRequest {
        id_token_hint,
        logout_hint,
        client_id,
        post_logout_redirect_uri,
        state: state.clone(),
        ui_locales,
    };

    let logout_query = serde_urlencoded::to_string(logout_request)?;

    // Add our parameters to the query, because the URL might already have one.
    let mut full_query = end_session_endpoint
        .query()
        .map(ToOwned::to_owned)
        .unwrap_or_default();
    if !full_query.is_empty() {
        full_query.push('&');
    }
    full_query.push_str(&logout_query);

    end_session_endpoint.set_query(Some(&full_query));

    Ok((end_session_endpoint, state))
}
