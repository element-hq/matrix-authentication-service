// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{convert::Infallible, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use headers::HeaderMapExt as _;
use mas_axum_utils::language_detection::AcceptLanguage;
use mas_i18n::{DataLocale, Translator, locale};

pub struct PreferredLanguage(pub DataLocale);

impl<S> FromRequestParts<S> for PreferredLanguage
where
    S: Send + Sync,
    Arc<Translator>: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let translator: Arc<Translator> = FromRef::from_ref(state);
        let accept_language = parts.headers.typed_get::<AcceptLanguage>();

        let iter = accept_language
            .iter()
            .flat_map(AcceptLanguage::iter)
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
