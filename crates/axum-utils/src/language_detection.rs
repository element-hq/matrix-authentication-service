// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::cmp::Reverse;

use headers::{Error, Header};
use http::{HeaderName, HeaderValue, header::ACCEPT_LANGUAGE};
use icu_locale_core::Locale;

#[derive(PartialEq, Eq, Debug)]
struct AcceptLanguagePart {
    // None means *
    locale: Option<Locale>,

    // Quality is between 0 and 1 with 3 decimal places
    // Which we map from 0 to 1000, e.g. 0.5 becomes 500
    quality: u16,
}

impl PartialOrd for AcceptLanguagePart {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AcceptLanguagePart {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // When comparing two AcceptLanguage structs, we only consider the
        // quality, in reverse.
        Reverse(self.quality).cmp(&Reverse(other.quality))
    }
}

/// A header that represents the `Accept-Language` header.
#[derive(PartialEq, Eq, Debug)]
pub struct AcceptLanguage {
    parts: Vec<AcceptLanguagePart>,
}

impl AcceptLanguage {
    pub fn iter(&self) -> impl Iterator<Item = &Locale> {
        // This should stop when we hit the first None, aka the first *
        self.parts.iter().map_while(|item| item.locale.as_ref())
    }
}

/// Utility to trim ASCII whitespace from the start and end of a byte slice
const fn trim_bytes(mut bytes: &[u8]) -> &[u8] {
    // Trim leading and trailing whitespace
    while let [first, rest @ ..] = bytes {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }

    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }

    bytes
}

impl Header for AcceptLanguage {
    fn name() -> &'static HeaderName {
        &ACCEPT_LANGUAGE
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let mut parts = Vec::new();
        for value in values {
            for part in value.as_bytes().split(|b| *b == b',') {
                let mut it = part.split(|b| *b == b';');
                let locale = it.next().ok_or(Error::invalid())?;
                let locale = trim_bytes(locale);

                let locale = match locale {
                    b"*" => None,
                    locale => {
                        let locale =
                            Locale::try_from_utf8(locale).map_err(|_e| Error::invalid())?;
                        Some(locale)
                    }
                };

                let quality = if let Some(quality) = it.next() {
                    let quality = trim_bytes(quality);
                    let quality = quality.strip_prefix(b"q=").ok_or(Error::invalid())?;
                    let quality = std::str::from_utf8(quality).map_err(|_e| Error::invalid())?;
                    let quality = quality.parse::<f64>().map_err(|_e| Error::invalid())?;
                    // Bound the quality between 0 and 1
                    let quality = quality.clamp(0_f64, 1_f64);

                    // Make sure the iterator is empty
                    if it.next().is_some() {
                        return Err(Error::invalid());
                    }

                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    {
                        f64::round(quality * 1000_f64) as u16
                    }
                } else {
                    1000
                };

                parts.push(AcceptLanguagePart { locale, quality });
            }
        }

        parts.sort();

        Ok(AcceptLanguage { parts })
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let mut value = String::new();
        let mut first = true;
        for part in &self.parts {
            if first {
                first = false;
            } else {
                value.push_str(", ");
            }

            if let Some(locale) = &part.locale {
                value.push_str(&locale.to_string());
            } else {
                value.push('*');
            }

            if part.quality != 1000 {
                value.push_str(";q=");
                value.push_str(&(f64::from(part.quality) / 1000_f64).to_string());
            }
        }

        // We know this is safe because we only use ASCII characters
        values.extend(Some(HeaderValue::from_str(&value).unwrap()));
    }
}

#[cfg(test)]
mod tests {
    use headers::HeaderMapExt;
    use http::{HeaderMap, HeaderValue, header::ACCEPT_LANGUAGE};
    use icu_locale_core::locale;

    use super::*;

    #[test]
    fn test_decode() {
        let headers = HeaderMap::from_iter([(
            ACCEPT_LANGUAGE,
            HeaderValue::from_str("fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5").unwrap(),
        )]);

        let accept_language: Option<AcceptLanguage> = headers.typed_get();
        assert!(accept_language.is_some());
        let accept_language = accept_language.unwrap();

        assert_eq!(
            accept_language,
            AcceptLanguage {
                parts: vec![
                    AcceptLanguagePart {
                        locale: Some(locale!("fr-CH")),
                        quality: 1000,
                    },
                    AcceptLanguagePart {
                        locale: Some(locale!("fr")),
                        quality: 900,
                    },
                    AcceptLanguagePart {
                        locale: Some(locale!("en")),
                        quality: 800,
                    },
                    AcceptLanguagePart {
                        locale: Some(locale!("de")),
                        quality: 700,
                    },
                    AcceptLanguagePart {
                        locale: None,
                        quality: 500,
                    },
                ]
            }
        );
    }

    #[test]
    /// Test that we can decode a header with multiple values unordered, and
    /// that the output is ordered by quality
    fn test_decode_order() {
        let headers = HeaderMap::from_iter([(
            ACCEPT_LANGUAGE,
            HeaderValue::from_str("*;q=0.5, fr-CH, en;q=0.8, fr;q=0.9, de;q=0.9").unwrap(),
        )]);

        let accept_language: Option<AcceptLanguage> = headers.typed_get();
        assert!(accept_language.is_some());
        let accept_language = accept_language.unwrap();

        assert_eq!(
            accept_language,
            AcceptLanguage {
                parts: vec![
                    AcceptLanguagePart {
                        locale: Some(locale!("fr-CH")),
                        quality: 1000,
                    },
                    AcceptLanguagePart {
                        locale: Some(locale!("fr")),
                        quality: 900,
                    },
                    AcceptLanguagePart {
                        locale: Some(locale!("de")),
                        quality: 900,
                    },
                    AcceptLanguagePart {
                        locale: Some(locale!("en")),
                        quality: 800,
                    },
                    AcceptLanguagePart {
                        locale: None,
                        quality: 500,
                    },
                ]
            }
        );
    }

    #[test]
    fn test_encode() {
        let accept_language = AcceptLanguage {
            parts: vec![
                AcceptLanguagePart {
                    locale: Some(locale!("fr-CH")),
                    quality: 1000,
                },
                AcceptLanguagePart {
                    locale: Some(locale!("fr")),
                    quality: 900,
                },
                AcceptLanguagePart {
                    locale: Some(locale!("de")),
                    quality: 900,
                },
                AcceptLanguagePart {
                    locale: Some(locale!("en")),
                    quality: 800,
                },
                AcceptLanguagePart {
                    locale: None,
                    quality: 500,
                },
            ],
        };

        let mut headers = HeaderMap::new();
        headers.typed_insert(accept_language);
        let header = headers.get(ACCEPT_LANGUAGE).unwrap();
        assert_eq!(
            header.to_str().unwrap(),
            "fr-CH, fr;q=0.9, de;q=0.9, en;q=0.8, *;q=0.5"
        );
    }
}
