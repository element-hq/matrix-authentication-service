// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{collections::HashMap, fs::File, io::BufReader, str::FromStr};

use camino::{Utf8Path, Utf8PathBuf};
use icu_experimental::relativetime::{
    RelativeTimeFormatter, RelativeTimeFormatterOptions, options::Numeric,
};
use icu_locale::{
    Locale,
    fallback::{LocaleFallbackPriority, LocaleFallbacker, LocaleFallbackerWithConfig},
};
use icu_plurals::PluralRules;
use icu_provider::{
    DataError, DataErrorKind, DataIdentifierBorrowed, DataLocale, DataMarker, DataRequest,
    DataRequestMetadata, data_marker, fallback::LocaleFallbackConfig,
};
use icu_provider_adapters::fallback::LocaleFallbackProvider;
use thiserror::Error;

use crate::{sprintf::Message, translations::TranslationTree};

data_marker!(
    /// Fake data key for errors
    MasTranslationV1,
    &'static str,
);

const FALLBACKER: LocaleFallbackerWithConfig<'static> = LocaleFallbacker::new().for_config({
    let mut config = LocaleFallbackConfig::default();
    config.priority = LocaleFallbackPriority::Language;
    config
});

/// Construct a [`DataRequest`] for the given locale
pub fn data_request_for_locale(locale: &DataLocale) -> DataRequest<'_> {
    let id = DataIdentifierBorrowed::for_locale(locale);
    let mut metadata = DataRequestMetadata::default();
    metadata.silent = true;
    DataRequest { id, metadata }
}

/// Error type for loading translations
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("Failed to load translation directory {path:?}")]
    ReadDir {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read translation file {path:?}")]
    ReadFile {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to deserialize translation file {path:?}")]
    Deserialize {
        path: Utf8PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Invalid locale for file {path:?}")]
    InvalidLocale {
        path: Utf8PathBuf,
        #[source]
        source: icu_locale::ParseError,
    },

    #[error("Invalid file name {path:?}")]
    InvalidFileName { path: Utf8PathBuf },
}

/// A translator for a set of translations.
#[derive(Debug)]
pub struct Translator {
    translations: HashMap<DataLocale, TranslationTree>,
    default_locale: DataLocale,
}

impl Translator {
    /// Create a new translator from a set of translations.
    #[must_use]
    pub fn new(translations: HashMap<DataLocale, TranslationTree>) -> Self {
        Self {
            translations,
            // TODO: make this configurable
            default_locale: icu_locale::locale!("en").into(),
        }
    }

    /// Load a set of translations from a directory.
    ///
    /// The directory should contain one JSON file per locale, with the locale
    /// being the filename without the extension, e.g. `en-US.json`.
    ///
    /// # Parameters
    ///
    /// * `path` - The path to load from.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be read, or if any of the files
    /// cannot be parsed.
    pub fn load_from_path(path: &Utf8Path) -> Result<Self, LoadError> {
        let mut translations = HashMap::new();

        let dir = path.read_dir_utf8().map_err(|source| LoadError::ReadDir {
            path: path.to_owned(),
            source,
        })?;

        for entry in dir {
            let entry = entry.map_err(|source| LoadError::ReadDir {
                path: path.to_owned(),
                source,
            })?;
            let path = entry.into_path();
            let Some(name) = path.file_stem() else {
                return Err(LoadError::InvalidFileName { path });
            };

            let locale: Locale = match Locale::from_str(name) {
                Ok(locale) => locale,
                Err(source) => return Err(LoadError::InvalidLocale { path, source }),
            };

            let file = match File::open(&path) {
                Ok(file) => file,
                Err(source) => return Err(LoadError::ReadFile { path, source }),
            };

            let mut reader = BufReader::new(file);

            let content = match serde_json::from_reader(&mut reader) {
                Ok(content) => content,
                Err(source) => return Err(LoadError::Deserialize { path, source }),
            };

            translations.insert(locale.into(), content);
        }

        Ok(Self::new(translations))
    }

    /// Get a message from the tree by key, with locale fallback.
    ///
    /// Returns the message and the locale it was found in.
    /// If the message is not found, returns `None`.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    #[must_use]
    pub fn message_with_fallback(
        &self,
        locale: DataLocale,
        key: &str,
    ) -> Option<(&Message, DataLocale)> {
        if let Ok(message) = self.message(&locale, key) {
            return Some((message, locale));
        }

        let mut iter = FALLBACKER.fallback_for(locale);

        loop {
            let locale = iter.get();

            if let Ok(message) = self.message(locale, key) {
                return Some((message, iter.take()));
            }

            // Try the defaut locale if we hit the `und` locale
            if locale.is_unknown() {
                let message = self.message(&self.default_locale, key).ok()?;
                return Some((message, self.default_locale));
            }

            iter.step();
        }
    }

    /// Get a message from the tree by key.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found, or if the
    /// requested key is not found.
    pub fn message(&self, locale: &DataLocale, key: &str) -> Result<&Message, DataError> {
        let request = data_request_for_locale(locale);

        let tree = self.translations.get(locale).ok_or_else(|| {
            DataErrorKind::IdentifierNotFound.with_req(MasTranslationV1::INFO, request)
        })?;

        let message = tree.message(key).ok_or_else(|| {
            DataErrorKind::IdentifierNotFound.with_req(MasTranslationV1::INFO, request)
        })?;

        Ok(message)
    }

    /// Get a plural message from the tree by key, with locale fallback.
    ///
    /// Returns the message and the locale it was found in.
    /// If the message is not found, returns `None`.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    /// * `count` - The count to use for pluralization.
    #[must_use]
    pub fn plural_with_fallback(
        &self,
        locale: DataLocale,
        key: &str,
        count: usize,
    ) -> Option<(&Message, DataLocale)> {
        let mut iter = FALLBACKER.fallback_for(locale);

        loop {
            let locale = iter.get();

            if let Ok(message) = self.plural(locale, key, count) {
                return Some((message, iter.take()));
            }

            // Stop if we hit the `und` locale
            if locale.is_unknown() {
                return None;
            }

            iter.step();
        }
    }

    /// Get a plural message from the tree by key.
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `key` - The key to look up, which is a dot-separated path.
    /// * `count` - The count to use for pluralization.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found, or if the
    /// requested key is not found.
    pub fn plural(
        &self,
        locale: &DataLocale,
        key: &str,
        count: usize,
    ) -> Result<&Message, DataError> {
        let fallbacker = LocaleFallbacker::new().static_to_owned();
        let plural_provider =
            LocaleFallbackProvider::new(icu_plurals::provider::Baked, fallbacker.clone());

        let plurals =
            PluralRules::try_new_cardinal_unstable(&plural_provider, locale.into_locale().into())?;
        let category = plurals.category_for(count);

        let request = data_request_for_locale(locale);

        let tree = self.translations.get(locale).ok_or_else(|| {
            DataErrorKind::IdentifierNotFound.with_req(MasTranslationV1::INFO, request)
        })?;

        let message = tree.pluralize(key, category).ok_or_else(|| {
            DataErrorKind::IdentifierNotFound.with_req(MasTranslationV1::INFO, request)
        })?;

        Ok(message)
    }

    /// Format a relative date
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `days` - The number of days to format, where 0 = today, 1 = tomorrow,
    ///   -1 = yesterday, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found.
    pub fn relative_date(&self, locale: &DataLocale, days: i64) -> Result<String, DataError> {
        // TODO: this is not using the fallbacker
        let formatter = RelativeTimeFormatter::try_new_long_day(
            locale.into_locale().into(),
            RelativeTimeFormatterOptions {
                numeric: Numeric::Auto,
            },
        )?;

        let date = formatter.format(days.into());
        Ok(date.to_string())
    }

    /// Format time
    ///
    /// # Parameters
    ///
    /// * `locale` - The locale to use.
    /// * `time` - The time to format.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested locale is not found.
    pub fn short_time(
        &self,
        locale: &DataLocale,
        time: icu_datetime::input::Time,
    ) -> Result<String, icu_datetime::DateTimeFormatterLoadError> {
        // TODO: this is not using the fallbacker
        let formatter = icu_datetime::NoCalendarFormatter::try_new(
            locale.into_locale().into(),
            icu_datetime::fieldsets::T::short(),
        )?;
        let time = formatter.format(&time);

        Ok(time.to_string())
    }

    /// Get a list of available locales.
    #[must_use]
    pub fn available_locales(&self) -> Vec<DataLocale> {
        self.translations.keys().cloned().collect()
    }

    /// Check if a locale is available.
    #[must_use]
    pub fn has_locale(&self, locale: &DataLocale) -> bool {
        self.translations.contains_key(locale)
    }

    /// Choose the best available locale from a list of candidates.
    #[must_use]
    pub fn choose_locale(&self, iter: impl Iterator<Item = DataLocale>) -> DataLocale {
        for locale in iter {
            if self.has_locale(&locale) {
                return locale;
            }

            let mut fallbacker = FALLBACKER.fallback_for(locale);

            loop {
                if fallbacker.get().is_unknown() {
                    break;
                }

                if self.has_locale(fallbacker.get()) {
                    return fallbacker.take();
                }
                fallbacker.step();
            }
        }

        self.default_locale
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use icu_locale::locale;

    use crate::{sprintf::arg_list, translator::Translator};

    fn translator() -> Translator {
        let root: Utf8PathBuf = env!("CARGO_MANIFEST_DIR").parse().unwrap();
        let test_data = root.join("test_data");
        Translator::load_from_path(&test_data).unwrap()
    }

    #[test]
    fn test_message() {
        let translator = translator();

        let message = translator.message(&locale!("en").into(), "hello").unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Hello!");

        let message = translator.message(&locale!("fr").into(), "hello").unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Bonjour !");

        let message = translator
            .message(&locale!("en-US").into(), "hello")
            .unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Hey!");

        // Try the fallback chain
        let result = translator.message(&locale!("en-US").into(), "goodbye");
        assert!(result.is_err());

        let (message, locale) = translator
            .message_with_fallback(locale!("en-US").into(), "goodbye")
            .unwrap();
        let formatted = message.format(&arg_list!()).unwrap();
        assert_eq!(formatted, "Goodbye!");
        assert_eq!(locale, locale!("en").into());
    }

    #[test]
    fn test_plurals() {
        let translator = translator();

        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 active session.");

        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 2)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 2)).unwrap();
        assert_eq!(formatted, "2 active sessions.");

        // In english, zero is plural
        let message = translator
            .plural(&locale!("en").into(), "active_sessions", 0)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 0)).unwrap();
        assert_eq!(formatted, "0 active sessions.");

        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 session active.");

        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 2)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 2)).unwrap();
        assert_eq!(formatted, "2 sessions actives.");

        // In french, zero is singular
        let message = translator
            .plural(&locale!("fr").into(), "active_sessions", 0)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 0)).unwrap();
        assert_eq!(formatted, "0 session active.");

        // Try the fallback chain
        let result = translator.plural(&locale!("en-US").into(), "active_sessions", 1);
        assert!(result.is_err());

        let (message, locale) = translator
            .plural_with_fallback(locale!("en-US").into(), "active_sessions", 1)
            .unwrap();
        let formatted = message.format(&arg_list!(count = 1)).unwrap();
        assert_eq!(formatted, "1 active session.");
        assert_eq!(locale, locale!("en").into());
    }
}
