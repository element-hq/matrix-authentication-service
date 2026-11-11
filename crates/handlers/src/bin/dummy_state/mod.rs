// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::Arc;

/// This is a dummy state, it should never be used.
///
/// It is only used to generate the API schemas, which does not execute any
/// request.
#[derive(Clone)]
pub struct DummyState;

macro_rules! impl_from_request_parts {
    ($type:ty) => {
        impl axum::extract::FromRequestParts<DummyState> for $type {
            type Rejection = std::convert::Infallible;

            fn from_request_parts(
                _parts: &mut axum::http::request::Parts,
                _state: &DummyState,
            ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
                async { unimplemented!("This is a dummy state, it should never be used") }
            }
        }
    };
}

macro_rules! impl_from_ref {
    ($type:ty) => {
        impl axum::extract::FromRef<DummyState> for $type {
            fn from_ref(_input: &DummyState) -> Self {
                unimplemented!("This is a dummy state, it should never be used")
            }
        }
    };
}

impl_from_request_parts!(mas_storage::BoxRepository);
impl_from_request_parts!(mas_data_model::BoxClock);
impl_from_request_parts!(mas_data_model::BoxRng);
impl_from_request_parts!(mas_handlers::ActivityTracker);
impl_from_request_parts!(mas_handlers::PreferredLanguage);
impl_from_request_parts!(mas_axum_utils::cookies::CookieJar);
impl_from_request_parts!(mas_policy::Policy);
impl_from_ref!(mas_router::UrlBuilder);
impl_from_ref!(mas_templates::Templates);
impl_from_ref!(Arc<dyn mas_matrix::HomeserverConnection>);
impl_from_ref!(mas_keystore::Keystore);
impl_from_ref!(mas_keystore::Encrypter);
impl_from_ref!(mas_handlers::passwords::PasswordManager);
impl_from_ref!(Arc<mas_policy::PolicyFactory>);
impl_from_ref!(mas_data_model::SiteConfig);
impl_from_ref!(mas_data_model::AppVersion);
impl_from_ref!(mas_handlers::GraphQLSchema);
impl_from_ref!(mas_handlers::Limiter);
impl_from_ref!(mas_handlers::MetadataCache);
impl_from_ref!(mas_storage::BoxRepositoryFactory);
impl_from_ref!(reqwest::Client);
impl_from_ref!(sqlx::PgPool);
