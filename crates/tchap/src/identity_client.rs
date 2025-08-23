//
// MIT License
//
// Copyright (c) 2025, Direction interministérielle du numérique - Gouvernement
// Français
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
//

//! This module provides utilities for interacting with the Matrix identity
//! server API.

use std::time::Duration;

use mas_data_model::TchapConfig;
use tracing::info;

/// Queries the identity server for information about an email address
///
/// # Parameters
///
/// * `email`: The email address to check///
/// # Returns
///
/// A Result containing either the JSON response or an error
pub async fn query_identity_server(
    email: &str,
    tchap_config: &TchapConfig,
) -> Result<serde_json::Value, reqwest::Error> {
    let identity_server_url = &tchap_config.identity_server_url;

    // Construct the URL with the email address
    let url = format!(
        "{}_matrix/identity/api/v1/internal-info?medium=email&address={}",
        identity_server_url, email
    );

    info!("Making request to identity server: {}", url);

    // Create a client with a timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // Make the HTTP request asynchronously
    // should use mas-http instead like SynapseConnection
    #[allow(clippy::disallowed_methods)]
    let response = client.get(&url).send().await?;

    // Parse the JSON response
    let json = response.json::<serde_json::Value>().await?;

    Ok(json)
}
