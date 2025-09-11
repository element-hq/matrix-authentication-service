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

use mas_data_model::TchapConfig;
use mas_http::RequestBuilderExt;
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
        "{}_matrix/identity/api/v1/internal-info",
        identity_server_url
    );
    let query_params = [("medium", "email"), ("address", email)];

    info!("Making request to identity server: {}", url);

    let http_client = mas_http::reqwest_client();

    // Make the HTTP request asynchronously
    let response = http_client
        .get(url)
        .query(&query_params)
        .send_traced()
        .await?;

    // Parse the JSON response
    let json = response.json::<serde_json::Value>().await?;

    Ok(json)
}
