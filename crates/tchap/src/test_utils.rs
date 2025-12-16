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

use mas_data_model::{EmailLookupFallbackRule, TchapConfig};
use url::Url;

pub fn test_tchap_config() -> TchapConfig {
    TchapConfig {
        identity_server_url: Url::parse("http://localhost:8091").unwrap(),
        email_lookup_fallback_rules: vec![EmailLookupFallbackRule {
            match_with: "@numerique.gouv.fr".to_string(),
            search: "@beta.gouv.fr".to_string(),
        }],
        tchap_app_link: Url::parse("https://test").unwrap(),
    }
}
