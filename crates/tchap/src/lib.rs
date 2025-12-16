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

//! Tchap-specific functionality for Matrix Authentication Service

extern crate tracing;
use mas_data_model::TchapConfig;
use mas_storage::BoxRepository;
use tracing::info;

mod identity_client;
mod test_utils;

/// Capitalise parts of a name containing different words, including those
/// separated by hyphens.
///
/// For example, 'John-Doe'
///
/// # Parameters
///
/// * `name`: The name to parse
///
/// # Returns
///
/// The capitalized name
#[must_use]
pub fn cap(name: &str) -> String {
    if name.is_empty() {
        return name.to_string();
    }

    // Split the name by whitespace then hyphens, capitalizing each part then
    // joining it back together.
    name.split_whitespace()
        .map(|space_part| {
            space_part
                .split('-')
                .map(|part| {
                    let mut chars = part.chars();
                    match chars.next() {
                        None => String::new(),
                        Some(first_char) => {
                            let first_char_upper = first_char.to_uppercase().collect::<String>();
                            let rest: String = chars.collect();
                            format!("{}{}", first_char_upper, rest)
                        }
                    }
                })
                .collect::<Vec<String>>()
                .join("-")
        })
        .collect::<Vec<String>>()
        .join(" ")
}

/// Generate a Matrix ID localpart from an email address.
///
/// This function:
/// 1. Replaces "@" with "-" in the email address
/// 2. Converts the email to lowercase
/// 3. Filters out any characters that are not allowed in a Matrix ID localpart
///
/// The allowed characters are: lowercase ASCII letters, digits, and "_-./="
///
/// # Parameters
///
/// * `address`: The email address to process
///
/// # Returns
///
/// A valid Matrix ID localpart derived from the email address
#[must_use]
pub fn email_to_mxid_localpart(address: &str) -> String {
    // Define the allowed characters for a Matrix ID localpart
    const ALLOWED_CHARS: &str = "abcdefghijklmnopqrstuvwxyz0123456789_-./=";

    // Replace "@" with "-" and convert to lowercase
    let processed = address.replace('@', "-").to_lowercase();

    // Filter out any characters that are not allowed
    processed
        .chars()
        .filter(|c| ALLOWED_CHARS.contains(*c))
        .collect()
}

/// Generate a display name from an email address based on specific rules.
///
/// This function:
/// 1. Replaces dots with spaces in the username part
/// 2. Determines the organization based on domain rules:
///    - gouv.fr emails use the subdomain or "gouv" if none
///    - other emails use the second-level domain
/// 3. Returns a display name in the format "Username [Organization]"
///
/// # Parameters
///
/// * `address`: The email address to process
///
/// # Returns
///
/// The formatted display name
#[must_use]
pub fn email_to_display_name(address: &str) -> String {
    // Split the part before and after the @ in the email.
    // Replace all . with spaces in the first part
    let parts: Vec<&str> = address.split('@').collect();
    if parts.len() != 2 {
        return String::new();
    }

    let username = parts[0].replace('.', " ");
    let domain = parts[1];

    // Figure out which org this email address belongs to
    let domain_parts: Vec<&str> = domain.split('.').collect();

    let org = if domain_parts.len() >= 2
        && domain_parts[domain_parts.len() - 2] == "gouv"
        && domain_parts[domain_parts.len() - 1] == "fr"
    {
        // Is this is a ...gouv.fr address, set the org to whatever is before
        // gouv.fr. If there isn't anything (a @gouv.fr email) simply mark their
        // org as "gouv"
        if domain_parts.len() > 2 {
            domain_parts[domain_parts.len() - 3]
        } else {
            "gouv"
        }
    } else if domain_parts.len() >= 2 {
        // Otherwise, mark their org as the email's second-level domain name
        domain_parts[domain_parts.len() - 2]
    } else {
        ""
    };

    // Format the display name
    format!("{} [{}]", cap(&username), cap(org))
}

/// Result of checking if an email is allowed on a server
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailAllowedResult {
    /// Email is allowed on this server
    Allowed,
    /// Email is mapped to a different server
    WrongServer,
    /// Server requires an invitation that is not present
    InvitationMissing,
}

/// Checks if an email address is allowed to be associated in the current server
///
/// This function makes an asynchronous GET request to the Matrix identity
/// server API to retrieve information about the home server associated with an
/// email address, then applies logic to determine if the email is allowed.
///
/// # Parameters
///
/// * `email`: The email address to check
/// * `server_name`: The name of the server to check against
///
/// # Returns
///
/// An `EmailAllowedResult` indicating whether the email is allowed and if not,
/// why
#[must_use]
pub async fn is_email_allowed(
    email: &str,
    server_name: &str,
    tchap_config: &TchapConfig,
) -> EmailAllowedResult {
    // Query the identity server
    match identity_client::query_identity_server(email, tchap_config).await {
        Ok(json) => {
            let hs = json.get("hs");

            // Check if "hs" is in the response or if hs different from server_name
            if hs.is_none() || hs.unwrap() != server_name {
                // Email is mapped to a different server or no server at all
                return EmailAllowedResult::WrongServer;
            }

            info!("hs: {} ", hs.unwrap());

            // Check if requires_invite is true and invited is false
            let requires_invite = json
                .get("requires_invite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let invited = json
                .get("invited")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            info!("requires_invite: {} invited: {}", requires_invite, invited);

            if requires_invite && !invited {
                // Requires an invite but hasn't been invited
                return EmailAllowedResult::InvitationMissing;
            }

            // All checks passed
            EmailAllowedResult::Allowed
        }
        Err(err) => {
            // Log the error and return WrongServer as a default error
            eprintln!("HTTP request failed: {}", err);
            EmailAllowedResult::WrongServer
        }
    }
}

/// Search for a user by email with fallback rules
///
/// # Parameters
/// * `repo` - Repository access
/// * `email` - The email to search for
/// * `fallback_rules` - Fallback rules for email transformation
///
/// # Returns
/// Option<`mas_data_model::User`> - The found user if any
pub async fn search_user_by_email(
    repo: &mut BoxRepository,
    email: &str,
    tchap_config: &TchapConfig,
) -> Result<Option<mas_data_model::User>, mas_storage::RepositoryError> {
    tracing::info!("Matching oidc identity by email:{}", email);
    let maybe_user_email = repo.user_email().find_by_email(email).await?;

    if let Some(user_email) = maybe_user_email {
        let maybe_user_found: Option<mas_data_model::User> =
            repo.user().lookup(user_email.user_id).await?;
        return Ok(maybe_user_found);
    }

    tracing::info!(
        "Email not found, Matching oidc identity by email using fallback rules:{}",
        email
    );
    let fallback_rules = &tchap_config.email_lookup_fallback_rules;
    // let fallback_rules: Value =
    //     serde_json::from_str(r#"[{"match":"@numerique.gouv.fr",
    // "search":"@beta.gouv.fr"}]"#)         .unwrap();

    // Iterate on fallback_rules, if a rule 'match' matches the email,
    // replace by value of 'search' and lookup again the email
    for rule in fallback_rules {
        let match_pattern = &rule.match_with;
        let search_value = &rule.search;
        tracing::info!(
            "Checking fallback rules {} : {}",
            match_pattern,
            search_value
        );

        // Check if email contains the match pattern
        if email.contains(match_pattern) {
            // Replace match pattern with search value
            let transformed_email = email.replace(match_pattern, search_value);
            tracing::debug!(
                "Search by transformed email fallback rules {}",
                transformed_email
            );

            // Look up the transformed email
            let maybe_transformed_user_email =
                repo.user_email().find_by_email(&transformed_email).await?;

            if let Some(transformed_user_email) = maybe_transformed_user_email {
                let user_found: Option<mas_data_model::User> =
                    repo.user().lookup(transformed_user_email.user_id).await?;
                tracing::info!(
                    "User found with fallback rules {} : {}",
                    match_pattern,
                    search_value
                );

                return Ok(user_found);
            }
        }
    }

    Ok(None)
}
//:tchap: end

pub use self::test_utils::*;

#[cfg(test)]
mod tests {
    use serde_json::json;
    use url::Url;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path, query_param},
    };

    use super::*;

    #[test]
    fn test_cap() {
        assert_eq!(cap("john"), "John");
        assert_eq!(cap("john-doe"), "John-Doe");
        assert_eq!(cap("john doe"), "John Doe");
        assert_eq!(cap("john-doe smith"), "John-Doe Smith");
        assert_eq!(cap(""), "");
    }

    #[test]
    fn test_email_to_display_name() {
        // Test gouv.fr email with subdomain
        assert_eq!(
            email_to_display_name("jane.smith@example.gouv.fr"),
            "Jane Smith [Example]"
        );

        // Test gouv.fr email without subdomain
        assert_eq!(email_to_display_name("user@gouv.fr"), "User [Gouv]");

        // Test gouv.fr email with subdomain
        assert_eq!(
            email_to_display_name("user@gendarmerie.gouv.fr"),
            "User [Gendarmerie]"
        );

        // Test gouv.fr email with subdomain
        assert_eq!(
            email_to_display_name("user@gendarmerie.interieur.gouv.fr"),
            "User [Interieur]"
        );

        // Test regular email
        assert_eq!(
            email_to_display_name("contact@example.com"),
            "Contact [Example]"
        );

        // Test invalid email
        assert_eq!(email_to_display_name("invalid-email"), "");
    }

    #[test]
    fn test_email_to_mxid_localpart() {
        // Test basic email
        assert_eq!(
            email_to_mxid_localpart("john.doe@example.com"),
            "john.doe-example.com"
        );

        // Test with uppercase letters
        assert_eq!(
            email_to_mxid_localpart("John.Doe@Example.com"),
            "john.doe-example.com"
        );

        // Test with special characters
        assert_eq!(
            email_to_mxid_localpart("user+tag@domain.com"),
            "usertag-domain.com"
        );

        // Test with invalid characters
        assert_eq!(
            email_to_mxid_localpart("user!#$%^&*()@domain.com"),
            "user-domain.com"
        );
    }

    #[tokio::test]
    async fn test_is_email_allowed() {
        let email = "user@example.org";
        let server_name = "homeserver1";
        let allowed = true;

        let mock_server = MockServer::start().await;

        let expected_calls = 1;

        let _mock_guard = Mock::given(method("GET"))
            .and(path("/_matrix/identity/api/v1/internal-info"))
            .and(query_param("medium", "email"))
            .and(query_param("address", email))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hs": server_name,
                "requires_invite": true,
                "invited": allowed
            })))
            .expect(expected_calls)
            .mount(&mock_server)
            .await;

        // Fake config
        let url = mock_server.uri() + "/";
        let config = TchapConfig {
            identity_server_url: Url::parse(url.as_str()).unwrap(),
            email_lookup_fallback_rules: vec![],
            tchap_app_link: Url::parse("https://test").unwrap(),
        };

        let result = is_email_allowed(email, server_name, &config).await;

        assert_eq!(result, EmailAllowedResult::Allowed);
    }

    #[tokio::test]
    async fn test_is_email_allowed_no_invitation() {
        let email = "user@example.org";
        let server_name = "homeserver1";
        let allowed = false;

        let mock_server = MockServer::start().await;

        let expected_calls = 1;

        let _mock_guard = Mock::given(method("GET"))
            .and(path("/_matrix/identity/api/v1/internal-info"))
            .and(query_param("medium", "email"))
            .and(query_param("address", email))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hs": server_name,
                "requires_invite": true,
                "invited": allowed
            })))
            .expect(expected_calls)
            .mount(&mock_server)
            .await;

        // Fake config
        let url = mock_server.uri() + "/";
        let config = TchapConfig {
            identity_server_url: Url::parse(url.as_str()).unwrap(),
            email_lookup_fallback_rules: vec![],
            tchap_app_link: Url::parse("https://test").unwrap(),
        };

        let result = is_email_allowed(email, server_name, &config).await;

        assert_eq!(result, EmailAllowedResult::InvitationMissing);
    }

    #[tokio::test]
    async fn test_is_email_allowed_wrong_server() {
        let email = "user@example.org";
        let server_name = "homeserver1";
        let allowed = true;

        let mock_server = MockServer::start().await;

        let expected_calls = 1;

        let _mock_guard = Mock::given(method("GET"))
            .and(path("/_matrix/identity/api/v1/internal-info"))
            .and(query_param("medium", "email"))
            .and(query_param("address", email))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hs": "homeserver2",
                "requires_invite": true,
                "invited": allowed
            })))
            .expect(expected_calls)
            .mount(&mock_server)
            .await;

        // Fake config
        let url = mock_server.uri() + "/";
        let config = TchapConfig {
            identity_server_url: Url::parse(url.as_str()).unwrap(),
            email_lookup_fallback_rules: vec![],
            tchap_app_link: Url::parse("https://test").unwrap(),
        };

        let result = is_email_allowed(email, server_name, &config).await;

        assert_eq!(result, EmailAllowedResult::WrongServer);
    }

    #[tokio::test]
    async fn test_is_email_allowed_with_special_character() {
        let email = "user+1@example.org";
        let server_name = "homeserver1";
        let allowed = true;

        let mock_server = MockServer::start().await;

        let expected_calls = 1;

        let _mock_guard = Mock::given(method("GET"))
            .and(path("/_matrix/identity/api/v1/internal-info"))
            .and(query_param("medium", "email"))
            .and(query_param("address", email))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "hs": server_name,
                "requires_invite": true,
                "invited": allowed
            })))
            .expect(expected_calls)
            .mount(&mock_server)
            .await;

        // Fake config
        let url = mock_server.uri() + "/";
        let config = TchapConfig {
            identity_server_url: Url::parse(url.as_str()).unwrap(),
            email_lookup_fallback_rules: vec![],
            tchap_app_link: Url::parse("https://test").unwrap(),
        };

        let result = is_email_allowed(email, server_name, &config).await;

        assert_eq!(result, EmailAllowedResult::Allowed);
    }
}
