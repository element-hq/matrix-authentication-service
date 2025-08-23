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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use url::Url;

use super::ConfigurationSection;

fn default_identity_server_url() -> Url {
    Url::parse("http://localhost:8090/").unwrap()
}

/// Tchap specific configuration
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TchapAppConfig {
    /// Identity Server Url
    #[serde(default = "default_identity_server_url")]
    pub identity_server_url: Url,

    /// Fallback Rules to use when linking an upstream account
    #[serde(default)]
    pub email_lookup_fallback_rules: Vec<EmailLookupFallbackRule>,
}

/// When linking the localpart, the email can be used to find the correct
/// localpart. By using the fallback rule, we can search for a Matrix account
/// with the `search` email pattern for an upstream account matching with the
/// `match_with` pattern
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug, Default, JsonSchema)]
pub struct EmailLookupFallbackRule {
    /// The upstream email pattern to match with when linking the localpart by
    /// email
    pub match_with: String,
    /// The email pattern to use for the search when linking the localpart by
    /// email
    pub search: String,
}

impl ConfigurationSection for TchapAppConfig {
    const PATH: Option<&'static str> = Some("tchap");

    // NOTE: implement this function to perform validation on config
    fn validate(
        &self,
        _figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    tchap:
                      identity_server_url: http://localhost:8091
                      email_lookup_fallback_rules:
                        - match_with : '@upstream.domain.tld'
                          search: '@matrix.domain.tld'
                ",
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<TchapAppConfig>("tchap")?;

            assert_eq!(
                &config.identity_server_url.as_str().to_owned(),
                "http://localhost:8091/"
            );

            assert_eq!(
                config.email_lookup_fallback_rules,
                vec![EmailLookupFallbackRule {
                    match_with: "@upstream.domain.tld".to_string(),
                    search: "@matrix.domain.tld".to_string(),
                }]
            );

            Ok(())
        });
    }
}
