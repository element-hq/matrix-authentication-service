// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{borrow::Cow, collections::HashMap};

use chrono::Duration;
use language_tags::LanguageTag;
use mas_iana::{
    jose::{JsonWebEncryptionAlg, JsonWebEncryptionEnc, JsonWebSignatureAlg},
    oauth::OAuthClientAuthenticationMethod,
};
use mas_jose::jwk::PublicJsonWebKeySet;
use serde::{
    Deserialize, Serialize,
    de::{DeserializeOwned, Error},
    ser::SerializeMap,
};
use serde_json::Value;
use serde_with::{DurationSeconds, serde_as, skip_serializing_none};
use url::Url;

use super::{ClientMetadata, Localized, VerifiedClientMetadata};
use crate::{
    oidc::{ApplicationType, SubjectType},
    requests::GrantType,
    response_type::ResponseType,
};

impl<T> Localized<T> {
    fn serialize<M>(&self, map: &mut M, field_name: &str) -> Result<(), M::Error>
    where
        M: SerializeMap,
        T: Serialize,
    {
        map.serialize_entry(field_name, &self.non_localized)?;

        for (lang, localized) in &self.localized {
            map.serialize_entry(&format!("{field_name}#{lang}"), localized)?;
        }

        Ok(())
    }

    fn deserialize(
        map: &mut HashMap<String, HashMap<Option<LanguageTag>, Value>>,
        field_name: &'static str,
    ) -> Result<Option<Self>, serde_json::Error>
    where
        T: DeserializeOwned,
    {
        let Some(map) = map.remove(field_name) else {
            return Ok(None);
        };

        let mut non_localized = None;
        let mut localized = HashMap::with_capacity(map.len() - 1);

        for (k, v) in map {
            let value = serde_json::from_value(v)?;

            if let Some(lang) = k {
                localized.insert(lang, value);
            } else {
                non_localized = Some(value);
            }
        }

        let non_localized = non_localized.ok_or_else(|| {
            serde_json::Error::custom(format!(
                "missing non-localized variant of field '{field_name}'"
            ))
        })?;

        Ok(Some(Localized {
            non_localized,
            localized,
        }))
    }
}

#[serde_as]
#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
pub struct ClientMetadataSerdeHelper {
    redirect_uris: Option<Vec<Url>>,
    response_types: Option<Vec<ResponseType>>,
    grant_types: Option<Vec<GrantType>>,
    application_type: Option<ApplicationType>,
    contacts: Option<Vec<String>>,
    jwks_uri: Option<Url>,
    jwks: Option<PublicJsonWebKeySet>,
    software_id: Option<String>,
    software_version: Option<String>,
    sector_identifier_uri: Option<Url>,
    subject_type: Option<SubjectType>,
    token_endpoint_auth_method: Option<OAuthClientAuthenticationMethod>,
    token_endpoint_auth_signing_alg: Option<JsonWebSignatureAlg>,
    id_token_signed_response_alg: Option<JsonWebSignatureAlg>,
    id_token_encrypted_response_alg: Option<JsonWebEncryptionAlg>,
    id_token_encrypted_response_enc: Option<JsonWebEncryptionEnc>,
    userinfo_signed_response_alg: Option<JsonWebSignatureAlg>,
    userinfo_encrypted_response_alg: Option<JsonWebEncryptionAlg>,
    userinfo_encrypted_response_enc: Option<JsonWebEncryptionEnc>,
    request_object_signing_alg: Option<JsonWebSignatureAlg>,
    request_object_encryption_alg: Option<JsonWebEncryptionAlg>,
    request_object_encryption_enc: Option<JsonWebEncryptionEnc>,
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    default_max_age: Option<Duration>,
    require_auth_time: Option<bool>,
    default_acr_values: Option<Vec<String>>,
    initiate_login_uri: Option<Url>,
    request_uris: Option<Vec<Url>>,
    require_signed_request_object: Option<bool>,
    require_pushed_authorization_requests: Option<bool>,
    introspection_signed_response_alg: Option<JsonWebSignatureAlg>,
    introspection_encrypted_response_alg: Option<JsonWebEncryptionAlg>,
    introspection_encrypted_response_enc: Option<JsonWebEncryptionEnc>,
    post_logout_redirect_uris: Option<Vec<Url>>,
    #[serde(flatten)]
    extra: ClientMetadataLocalizedFields,
}

impl From<VerifiedClientMetadata> for ClientMetadataSerdeHelper {
    fn from(metadata: VerifiedClientMetadata) -> Self {
        metadata.inner.into()
    }
}

impl From<ClientMetadata> for ClientMetadataSerdeHelper {
    fn from(metadata: ClientMetadata) -> Self {
        let ClientMetadata {
            redirect_uris,
            response_types,
            grant_types,
            application_type,
            contacts,
            client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks_uri,
            jwks,
            software_id,
            software_version,
            sector_identifier_uri,
            subject_type,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            id_token_signed_response_alg,
            id_token_encrypted_response_alg,
            id_token_encrypted_response_enc,
            userinfo_signed_response_alg,
            userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc,
            request_object_signing_alg,
            request_object_encryption_alg,
            request_object_encryption_enc,
            default_max_age,
            require_auth_time,
            default_acr_values,
            initiate_login_uri,
            request_uris,
            require_signed_request_object,
            require_pushed_authorization_requests,
            introspection_signed_response_alg,
            introspection_encrypted_response_alg,
            introspection_encrypted_response_enc,
            post_logout_redirect_uris,
        } = metadata;

        ClientMetadataSerdeHelper {
            redirect_uris,
            response_types,
            grant_types,
            application_type,
            contacts,
            jwks_uri,
            jwks,
            software_id,
            software_version,
            sector_identifier_uri,
            subject_type,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            id_token_signed_response_alg,
            id_token_encrypted_response_alg,
            id_token_encrypted_response_enc,
            userinfo_signed_response_alg,
            userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc,
            request_object_signing_alg,
            request_object_encryption_alg,
            request_object_encryption_enc,
            default_max_age,
            require_auth_time,
            default_acr_values,
            initiate_login_uri,
            request_uris,
            require_signed_request_object,
            require_pushed_authorization_requests,
            introspection_signed_response_alg,
            introspection_encrypted_response_alg,
            introspection_encrypted_response_enc,
            post_logout_redirect_uris,
            extra: ClientMetadataLocalizedFields {
                client_name,
                logo_uri,
                client_uri,
                policy_uri,
                tos_uri,
            },
        }
    }
}

impl From<ClientMetadataSerdeHelper> for ClientMetadata {
    fn from(metadata: ClientMetadataSerdeHelper) -> Self {
        let ClientMetadataSerdeHelper {
            redirect_uris,
            response_types,
            grant_types,
            application_type,
            contacts,
            jwks_uri,
            jwks,
            software_id,
            software_version,
            sector_identifier_uri,
            subject_type,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            id_token_signed_response_alg,
            id_token_encrypted_response_alg,
            id_token_encrypted_response_enc,
            userinfo_signed_response_alg,
            userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc,
            request_object_signing_alg,
            request_object_encryption_alg,
            request_object_encryption_enc,
            default_max_age,
            require_auth_time,
            default_acr_values,
            initiate_login_uri,
            request_uris,
            require_signed_request_object,
            require_pushed_authorization_requests,
            introspection_signed_response_alg,
            introspection_encrypted_response_alg,
            introspection_encrypted_response_enc,
            post_logout_redirect_uris,
            extra:
                ClientMetadataLocalizedFields {
                    client_name,
                    logo_uri,
                    client_uri,
                    policy_uri,
                    tos_uri,
                },
        } = metadata;

        ClientMetadata {
            redirect_uris,
            response_types,
            grant_types,
            application_type,
            contacts,
            client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
            jwks_uri,
            jwks,
            software_id,
            software_version,
            sector_identifier_uri,
            subject_type,
            token_endpoint_auth_method,
            token_endpoint_auth_signing_alg,
            id_token_signed_response_alg,
            id_token_encrypted_response_alg,
            id_token_encrypted_response_enc,
            userinfo_signed_response_alg,
            userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc,
            request_object_signing_alg,
            request_object_encryption_alg,
            request_object_encryption_enc,
            default_max_age,
            require_auth_time,
            default_acr_values,
            initiate_login_uri,
            request_uris,
            require_signed_request_object,
            require_pushed_authorization_requests,
            introspection_signed_response_alg,
            introspection_encrypted_response_alg,
            introspection_encrypted_response_enc,
            post_logout_redirect_uris,
        }
    }
}

struct ClientMetadataLocalizedFields {
    client_name: Option<Localized<String>>,
    logo_uri: Option<Localized<Url>>,
    client_uri: Option<Localized<Url>>,
    policy_uri: Option<Localized<Url>>,
    tos_uri: Option<Localized<Url>>,
}

impl Serialize for ClientMetadataLocalizedFields {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        if let Some(client_name) = &self.client_name {
            client_name.serialize(&mut map, "client_name")?;
        }

        if let Some(logo_uri) = &self.logo_uri {
            logo_uri.serialize(&mut map, "logo_uri")?;
        }

        if let Some(client_uri) = &self.client_uri {
            client_uri.serialize(&mut map, "client_uri")?;
        }

        if let Some(policy_uri) = &self.policy_uri {
            policy_uri.serialize(&mut map, "policy_uri")?;
        }

        if let Some(tos_uri) = &self.tos_uri {
            tos_uri.serialize(&mut map, "tos_uri")?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for ClientMetadataLocalizedFields {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = HashMap::<Cow<'de, str>, Value>::deserialize(deserializer)?;
        let mut new_map: HashMap<String, HashMap<Option<LanguageTag>, Value>> = HashMap::new();

        for (k, v) in map {
            let (prefix, lang) = if let Some((prefix, lang)) = k.split_once('#') {
                let lang = LanguageTag::parse(lang).map_err(|_| {
                    D::Error::invalid_value(serde::de::Unexpected::Str(lang), &"language tag")
                })?;
                (prefix.to_owned(), Some(lang))
            } else {
                (k.into_owned(), None)
            };

            new_map.entry(prefix).or_default().insert(lang, v);
        }

        let client_name =
            Localized::deserialize(&mut new_map, "client_name").map_err(D::Error::custom)?;

        let logo_uri =
            Localized::deserialize(&mut new_map, "logo_uri").map_err(D::Error::custom)?;

        let client_uri =
            Localized::deserialize(&mut new_map, "client_uri").map_err(D::Error::custom)?;

        let policy_uri =
            Localized::deserialize(&mut new_map, "policy_uri").map_err(D::Error::custom)?;

        let tos_uri = Localized::deserialize(&mut new_map, "tos_uri").map_err(D::Error::custom)?;

        Ok(Self {
            client_name,
            logo_uri,
            client_uri,
            policy_uri,
            tos_uri,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_localized_fields() {
        let metadata = serde_json::json!({
            "redirect_uris": ["http://localhost/oidc"],
            "client_name": "Postbox",
            "client_name#fr": "Boîte à lettres",
            "client_uri": "https://localhost/",
            "client_uri#fr": "https://localhost/fr",
            "client_uri#de": "https://localhost/de",
        });

        let metadata: ClientMetadata = serde_json::from_value(metadata).unwrap();

        let name = metadata.client_name.unwrap();
        assert_eq!(name.non_localized(), "Postbox");
        assert_eq!(
            name.get(Some(&LanguageTag::parse("fr").unwrap())).unwrap(),
            "Boîte à lettres"
        );
        assert_eq!(name.get(Some(&LanguageTag::parse("de").unwrap())), None);

        let client_uri = metadata.client_uri.unwrap();
        assert_eq!(client_uri.non_localized().as_ref(), "https://localhost/");
        assert_eq!(
            client_uri
                .get(Some(&LanguageTag::parse("fr").unwrap()))
                .unwrap()
                .as_ref(),
            "https://localhost/fr"
        );
        assert_eq!(
            client_uri
                .get(Some(&LanguageTag::parse("de").unwrap()))
                .unwrap()
                .as_ref(),
            "https://localhost/de"
        );
    }

    #[test]
    fn serialize_localized_fields() {
        let client_name = Localized::new(
            "Postbox".to_owned(),
            [(
                LanguageTag::parse("fr").unwrap(),
                "Boîte à lettres".to_owned(),
            )],
        );
        let client_uri = Localized::new(
            Url::parse("https://localhost").unwrap(),
            [
                (
                    LanguageTag::parse("fr").unwrap(),
                    Url::parse("https://localhost/fr").unwrap(),
                ),
                (
                    LanguageTag::parse("de").unwrap(),
                    Url::parse("https://localhost/de").unwrap(),
                ),
            ],
        );
        let metadata = ClientMetadata {
            redirect_uris: Some(vec![Url::parse("http://localhost/oidc").unwrap()]),
            client_name: Some(client_name),
            client_uri: Some(client_uri),
            ..Default::default()
        }
        .validate()
        .unwrap();

        assert_eq!(
            serde_json::to_value(metadata).unwrap(),
            serde_json::json!({
                "redirect_uris": ["http://localhost/oidc"],
                "client_name": "Postbox",
                "client_name#fr": "Boîte à lettres",
                "client_uri": "https://localhost/",
                "client_uri#fr": "https://localhost/fr",
                "client_uri#de": "https://localhost/de",
            })
        );
    }
}
