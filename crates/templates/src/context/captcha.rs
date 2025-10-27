// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::BTreeMap, sync::Arc};

use mas_i18n::DataLocale;
use minijinja::{
    Value,
    value::{Enumerator, Object},
};
use rand::Rng;
use serde::Serialize;

use crate::{TemplateContext, context::SampleIdentifier};

#[derive(Debug)]
struct CaptchaConfig(mas_data_model::CaptchaConfig);

impl Object for CaptchaConfig {
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        match key.as_str() {
            Some("service") => Some(match &self.0.service {
                mas_data_model::CaptchaService::RecaptchaV2 => "recaptcha_v2".into(),
                mas_data_model::CaptchaService::CloudflareTurnstile => {
                    "cloudflare_turnstile".into()
                }
                mas_data_model::CaptchaService::HCaptcha => "hcaptcha".into(),
            }),
            Some("site_key") => Some(self.0.site_key.clone().into()),
            _ => None,
        }
    }

    fn enumerate(self: &Arc<Self>) -> Enumerator {
        Enumerator::Str(&["service", "site_key"])
    }
}

/// Context with an optional CAPTCHA configuration in it
#[derive(Serialize)]
pub struct WithCaptcha<T> {
    captcha: Option<Value>,

    #[serde(flatten)]
    inner: T,
}

impl<T> WithCaptcha<T> {
    #[must_use]
    pub(crate) fn new(captcha: Option<mas_data_model::CaptchaConfig>, inner: T) -> Self {
        Self {
            captcha: captcha.map(|captcha| Value::from_object(CaptchaConfig(captcha))),
            inner,
        }
    }
}

impl<T: TemplateContext> TemplateContext for WithCaptcha<T> {
    fn sample<R: Rng + Clone>(
        now: chrono::DateTime<chrono::prelude::Utc>,
        rng: &mut R,
        locales: &[DataLocale],
    ) -> BTreeMap<SampleIdentifier, Self>
    where
        Self: Sized,
    {
        T::sample(now, rng, locales)
            .into_iter()
            .map(|(k, inner)| (k, Self::new(None, inner)))
            .collect()
    }
}
