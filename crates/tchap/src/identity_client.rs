//! This module provides utilities for interacting with the Matrix identity
//! server API.

use std::time::Duration;

use tracing::info;
use url::Url;

fn default_identity_server_url() -> Url {
    // Try to read the TCHAP_IDENTITY_SERVER_URL environment variable
    match std::env::var("TCHAP_IDENTITY_SERVER_URL") {
        Ok(url_str) => {
            // Attempt to parse the URL from the environment variable
            match Url::parse(&url_str) {
                Ok(url) => {
                    // Success: use the URL from the environment variable
                    return url;
                }
                Err(err) => {
                    // Parsing error: log a warning and use the default value
                    tracing::warn!(
                        "The TCHAP_IDENTITY_SERVER_URL environment variable contains an invalid URL: {}. Using default value.",
                        err
                    );
                }
            }
        }
        Err(std::env::VarError::NotPresent) => {
            // Variable not defined: use the default value without warning
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            // Variable contains non-Unicode characters: log a warning
            tracing::warn!(
                "The TCHAP_IDENTITY_SERVER_URL environment variable contains non-Unicode characters. Using default value."
            );
        }
    }

    // Default value if the environment variable is not defined or invalid
    Url::parse("http://localhost:8090").unwrap()
}

/// Queries the identity server for information about an email address
///
/// # Parameters
///
/// * `email`: The email address to check///
/// # Returns
///
/// A Result containing either the JSON response or an error
pub async fn query_identity_server(email: &str) -> Result<serde_json::Value, reqwest::Error> {
    let identity_server_url = default_identity_server_url();

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
