// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{convert::Infallible, sync::Arc};

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use axum_extra::typed_header::TypedHeader;
use mas_axum_utils::language_detection::AcceptLanguage;
use mas_i18n::{locale, DataLocale, Translator};

pub struct PreferredLanguage(pub DataLocale);

#[async_trait]
impl<S> FromRequestParts<S> for PreferredLanguage
where
    S: Send + Sync,
    Arc<Translator>: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let translator: Arc<Translator> = FromRef::from_ref(state);
        let accept_language: Option<TypedHeader<AcceptLanguage>> =
            FromRequestParts::from_request_parts(parts, state).await?;

        let iter = accept_language
            .iter()
            .flat_map(|TypedHeader(accept_language)| accept_language.iter())
            .flat_map(|lang| {
                let lang = DataLocale::from(lang);
                // XXX: this is hacky as we may want to actually maintain proper language
                // aliases at some point, but `zh-CN` doesn't fallback
                // automatically to `zh-Hans`, so we insert it manually here.
                // For some reason, `zh-TW` does fallback to `zh-Hant` correctly.
                if lang == locale!("zh-CN").into() {
                    vec![lang, locale!("zh-Hans").into()]
                } else {
                    vec![lang]
                }
            });

        let locale = translator.choose_locale(iter);

        Ok(PreferredLanguage(locale))
    }
}
