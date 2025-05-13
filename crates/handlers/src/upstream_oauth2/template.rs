// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashMap, sync::Arc};

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding};
use minijinja::{
    Environment, Error, ErrorKind, Value,
    value::{Enumerator, Object},
};
use tchap;

/// Context passed to the attribute mapping template
///
/// The variables available in the template are:
/// - `user`: claims for the user, merged from the ID token and userinfo
///   endpoint
/// - `id_token_claims`: claims from the ID token
/// - `userinfo_claims`: claims from the userinfo endpoint
/// - `extra_callback_parameters`: extra parameters passed to the callback
#[derive(Debug, Default)]
pub(crate) struct AttributeMappingContext {
    id_token_claims: Option<HashMap<String, serde_json::Value>>,
    extra_callback_parameters: Option<serde_json::Value>,
    userinfo_claims: Option<serde_json::Value>,
}

impl AttributeMappingContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_id_token_claims(
        mut self,
        id_token_claims: HashMap<String, serde_json::Value>,
    ) -> Self {
        self.id_token_claims = Some(id_token_claims);
        self
    }

    pub fn with_extra_callback_parameters(
        mut self,
        extra_callback_parameters: serde_json::Value,
    ) -> Self {
        self.extra_callback_parameters = Some(extra_callback_parameters);
        self
    }

    pub fn with_userinfo_claims(mut self, userinfo_claims: serde_json::Value) -> Self {
        self.userinfo_claims = Some(userinfo_claims);
        self
    }

    pub fn build(self) -> Value {
        Value::from_object(self)
    }
}

impl Object for AttributeMappingContext {
    fn get_value(self: &Arc<Self>, name: &Value) -> Option<Value> {
        match name.as_str()? {
            "user" => {
                if self.id_token_claims.is_none() && self.userinfo_claims.is_none() {
                    return None;
                }
                let mut merged_user: HashMap<String, serde_json::Value> = HashMap::new();
                if let serde_json::Value::Object(userinfo) = self
                    .userinfo_claims
                    .clone()
                    .unwrap_or(serde_json::Value::Null)
                {
                    merged_user.extend(userinfo);
                }
                if let Some(id_token) = self.id_token_claims.clone() {
                    merged_user.extend(id_token);
                }
                Some(Value::from_serialize(merged_user))
            }
            "id_token_claims" => self.id_token_claims.as_ref().map(Value::from_serialize),
            "userinfo_claims" => self.userinfo_claims.as_ref().map(Value::from_serialize),
            "extra_callback_parameters" => self
                .extra_callback_parameters
                .as_ref()
                .map(Value::from_serialize),
            _ => None,
        }
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        let mut attrs = Vec::new();
        if self.id_token_claims.is_some() || self.userinfo_claims.is_none() {
            attrs.push(minijinja::Value::from("user"));
        }
        if self.id_token_claims.is_some() {
            attrs.push(minijinja::Value::from("id_token_claims"));
        }
        if self.userinfo_claims.is_some() {
            attrs.push(minijinja::Value::from("userinfo_claims"));
        }
        if self.extra_callback_parameters.is_some() {
            attrs.push(minijinja::Value::from("extra_callback_parameters"));
        }
        Enumerator::Values(attrs)
    }
}

fn b64decode(value: &str) -> Result<Value, Error> {
    // We're not too concerned about the performance of this filter, so we'll just
    // try all the base64 variants when decoding
    let bytes = Base64::decode_vec(value)
        .or_else(|_| Base64Url::decode_vec(value))
        .or_else(|_| Base64Unpadded::decode_vec(value))
        .or_else(|_| Base64UrlUnpadded::decode_vec(value))
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidOperation,
                "Failed to decode base64 string",
            )
            .with_source(e)
        })?;

    // It is not obvious, but the cleanest way to get a Value stored as raw bytes is
    // to wrap it in an Arc, because Value implements From<Arc<Vec<u8>>>
    Ok(Value::from(Arc::new(bytes)))
}

fn b64encode(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// Decode a Tag-Length-Value encoded byte array into a map of tag to value.
fn tlvdecode(bytes: &[u8]) -> Result<HashMap<Value, Value>, Error> {
    let mut iter = bytes.iter().copied();
    let mut ret = HashMap::new();
    loop {
        // TODO: this assumes the tag and the length are both single bytes, which is not
        // always the case with protobufs. We should properly decode varints
        // here.
        let Some(tag) = iter.next() else {
            break;
        };

        let len = iter
            .next()
            .ok_or_else(|| Error::new(ErrorKind::InvalidOperation, "Invalid ILV encoding"))?;

        let mut bytes = Vec::with_capacity(len.into());
        for _ in 0..len {
            bytes.push(
                iter.next().ok_or_else(|| {
                    Error::new(ErrorKind::InvalidOperation, "Invalid ILV encoding")
                })?,
            );
        }

        ret.insert(tag.into(), Value::from(Arc::new(bytes)));
    }

    Ok(ret)
}

fn string(value: &Value) -> String {
    value.to_string()
}

fn from_json(value: &str) -> Result<Value, minijinja::Error> {
    let value: serde_json::Value = serde_json::from_str(value).map_err(|e| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Failed to decode JSON",
        )
        .with_source(e)
    })?;

    Ok(Value::from_serialize(value))
}

pub fn environment() -> Environment<'static> {
    let mut env = Environment::new();

    minijinja_contrib::add_to_environment(&mut env);

    env.add_filter("b64decode", b64decode);
    env.add_filter("b64encode", b64encode);
    env.add_filter("tlvdecode", tlvdecode);
    env.add_filter("string", string);
    env.add_filter("from_json", from_json);

    // Add Tchap-specific filters, this could be a generic config submitted
    // to upstream allowing all users to add their own filters without upstream code
    // modifications tester les fonctions async pour le reseau
    env.add_filter("email_to_display_name", |s: &str| {
        tchap::email_to_display_name(s)
    });
    env.add_filter("email_to_mxid_localpart", |s: &str| {
        tchap::email_to_mxid_localpart(s)
    });

    env.set_unknown_method_callback(minijinja_contrib::pycompat::unknown_method_callback);

    env
}

#[cfg(test)]
mod tests {
    use super::environment;

    #[test]
    fn test_split() {
        let env = environment();
        let res = env
            .render_str(r#"{{ 'foo, bar' | split(', ') | join(" | ") }}"#, ())
            .unwrap();
        assert_eq!(res, "foo | bar");
    }

    #[test]
    fn test_ilvdecode() {
        let env = environment();
        let res = env
            .render_str(
                r#"
                    {%- set tlv = 'Cg0wLTM4NS0yODA4OS0wEgRtb2Nr' | b64decode | tlvdecode -%}
                    {%- if tlv[18]|string != 'mock' -%}
                        {{ "FAIL"/0 }}
                    {%- endif -%}
                    {{- tlv[10]|string -}}
                "#,
                (),
            )
            .unwrap();
        assert_eq!(res, "0-385-28089-0");
    }

    #[test]
    fn test_base64_decode() {
        let env = environment();

        let res = env
            .render_str("{{ 'cGFkZGluZw==' | b64decode }}", ())
            .unwrap();
        assert_eq!(res, "padding");

        let res = env
            .render_str("{{ 'dW5wYWRkZWQ' | b64decode }}", ())
            .unwrap();
        assert_eq!(res, "unpadded");
    }
}
