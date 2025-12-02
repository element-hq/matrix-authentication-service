// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// This is needed to make the Environment::add* functions work
#![allow(clippy::needless_pass_by_value)]

//! Additional functions, tests and filters used in templates

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Formatter,
    str::FromStr,
    sync::{Arc, atomic::AtomicUsize},
};

use camino::Utf8Path;
use mas_i18n::{Argument, ArgumentList, DataLocale, Translator, sprintf::FormattedMessagePart};
use mas_router::UrlBuilder;
use mas_spa::ViteManifest;
use minijinja::{
    Error, ErrorKind, State, Value, escape_formatter,
    machinery::make_string_output,
    value::{Kwargs, Object, ViaDeserialize, from_args},
};
use url::Url;

pub fn register(
    env: &mut minijinja::Environment,
    url_builder: UrlBuilder,
    vite_manifest: Option<ViteManifest>,
    translator: Arc<Translator>,
) {
    env.set_unknown_method_callback(minijinja_contrib::pycompat::unknown_method_callback);

    minijinja_contrib::add_to_environment(env);
    env.add_test("empty", self::tester_empty);
    env.add_filter("to_params", filter_to_params);
    env.add_filter("simplify_url", filter_simplify_url);
    env.add_filter("add_slashes", filter_add_slashes);
    env.add_filter("parse_user_agent", filter_parse_user_agent);
    env.add_filter("id_color_hash", filter_id_color_hash);
    env.add_function("add_params_to_url", function_add_params_to_url);
    env.add_function("counter", || Ok(Value::from_object(Counter::default())));
    if let Some(vite_manifest) = vite_manifest {
        env.add_global(
            "include_asset",
            Value::from_object(IncludeAsset {
                url_builder: url_builder.clone(),
                vite_manifest,
            }),
        );
    } else {
        env.add_global("include_asset", Value::from_object(FakeIncludeAsset {}));
    }
    env.add_global(
        "translator",
        Value::from_object(TranslatorFunc { translator }),
    );
    env.add_filter("prefix_url", move |url: &str| -> String {
        if !url.starts_with('/') {
            // Let's assume it's not an internal URL and return it as-is
            return url.to_owned();
        }

        let Some(prefix) = url_builder.prefix() else {
            // If there is no prefix to add, return the URL as-is
            return url.to_owned();
        };

        format!("{prefix}{url}")
    });
}

fn tester_empty(seq: Value) -> bool {
    seq.len() == Some(0)
}

fn filter_add_slashes(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\"', "\\\"")
        .replace('\'', "\\\'")
}

fn filter_to_params(params: &Value, kwargs: Kwargs) -> Result<String, Error> {
    let params = serde_urlencoded::to_string(params).map_err(|e| {
        Error::new(
            ErrorKind::InvalidOperation,
            "Could not serialize parameters",
        )
        .with_source(e)
    })?;

    let prefix = kwargs.get("prefix").unwrap_or("");
    kwargs.assert_all_used()?;

    if params.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("{prefix}{params}"))
    }
}

/// Filter which simplifies a URL to its domain name for HTTP(S) URLs
fn filter_simplify_url(url: &str, kwargs: Kwargs) -> Result<String, minijinja::Error> {
    // Do nothing if the URL is not valid
    let Ok(mut url) = Url::from_str(url) else {
        return Ok(url.to_owned());
    };

    // Always at least remove the query parameters and fragment
    url.set_query(None);
    url.set_fragment(None);

    // Do nothing else for non-HTTPS URLs
    if url.scheme() != "https" {
        return Ok(url.to_string());
    }

    let keep_path = kwargs.get::<Option<bool>>("keep_path")?.unwrap_or_default();
    kwargs.assert_all_used()?;

    // Only return the domain name
    let Some(domain) = url.domain() else {
        return Ok(url.to_string());
    };

    if keep_path {
        Ok(format!(
            "{domain}{path}",
            domain = domain,
            path = url.path(),
        ))
    } else {
        Ok(domain.to_owned())
    }
}

/// Filter which computes a hash between 1 and 6 of an input string, similar to
/// compound-web's useIdColorHash
fn filter_id_color_hash(input: &str) -> u32 {
    input.chars().fold(0, |hash, c| hash + c as u32) % 6 + 1
}

/// Filter which parses a user-agent string
fn filter_parse_user_agent(user_agent: String) -> Value {
    let user_agent = mas_data_model::UserAgent::parse(user_agent);
    Value::from_serialize(user_agent)
}

enum ParamsWhere {
    Fragment,
    Query,
}

fn function_add_params_to_url(
    uri: ViaDeserialize<Url>,
    mode: &str,
    params: ViaDeserialize<HashMap<String, Value>>,
) -> Result<String, Error> {
    use ParamsWhere::{Fragment, Query};

    let mode = match mode {
        "fragment" => Fragment,
        "query" => Query,
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidOperation,
                "Invalid `mode` parameter",
            ));
        }
    };

    // First, get the `uri`, `mode` and `params` parameters
    // Get the relevant part of the URI and parse for existing parameters
    let existing = match mode {
        Fragment => uri.fragment(),
        Query => uri.query(),
    };
    let existing: HashMap<String, Value> = existing
        .map(serde_urlencoded::from_str)
        .transpose()
        .map_err(|e| {
            Error::new(
                ErrorKind::InvalidOperation,
                "Could not parse existing `uri` parameters",
            )
            .with_source(e)
        })?
        .unwrap_or_default();

    // Merge the exising and the additional parameters together
    // Use a BTreeMap for determinism (because it orders keys)
    let params: BTreeMap<&String, &Value> = params.iter().chain(existing.iter()).collect();

    // Transform them back to urlencoded
    let params = serde_urlencoded::to_string(params).map_err(|e| {
        Error::new(
            ErrorKind::InvalidOperation,
            "Could not serialize back parameters",
        )
        .with_source(e)
    })?;

    let uri = {
        let mut uri = uri;
        match mode {
            Fragment => uri.set_fragment(Some(&params)),
            Query => uri.set_query(Some(&params)),
        }
        uri
    };

    Ok(uri.to_string())
}

struct TranslatorFunc {
    translator: Arc<Translator>,
}

impl std::fmt::Debug for TranslatorFunc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranslatorFunc")
            .field("translator", &"..")
            .finish()
    }
}

impl std::fmt::Display for TranslatorFunc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("translator")
    }
}

impl Object for TranslatorFunc {
    fn call(self: &Arc<Self>, _state: &State, args: &[Value]) -> Result<Value, Error> {
        let (lang,): (&str,) = from_args(args)?;

        let lang: DataLocale = lang.parse().map_err(|e| {
            Error::new(ErrorKind::InvalidOperation, "Invalid language").with_source(e)
        })?;

        Ok(Value::from_object(TranslateFunc {
            lang,
            translator: Arc::clone(&self.translator),
        }))
    }
}

struct TranslateFunc {
    translator: Arc<Translator>,
    lang: DataLocale,
}

impl std::fmt::Debug for TranslateFunc {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Translate")
            .field("translator", &"..")
            .field("lang", &self.lang)
            .finish()
    }
}

impl std::fmt::Display for TranslateFunc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("translate")
    }
}

impl Object for TranslateFunc {
    fn call(self: &Arc<Self>, state: &State, args: &[Value]) -> Result<Value, Error> {
        let (key, kwargs): (&str, Kwargs) = from_args(args)?;

        let (message, _locale) = if let Some(count) = kwargs.get("count")? {
            self.translator
                .plural_with_fallback(self.lang.clone(), key, count)
                .ok_or(Error::new(
                    ErrorKind::InvalidOperation,
                    "Missing translation",
                ))?
        } else {
            self.translator
                .message_with_fallback(self.lang.clone(), key)
                .ok_or(Error::new(
                    ErrorKind::InvalidOperation,
                    "Missing translation",
                ))?
        };

        let res: Result<ArgumentList, Error> = kwargs
            .args()
            .map(|name| {
                let value: Value = kwargs.get(name)?;
                let value = serde_json::to_value(value).map_err(|e| {
                    Error::new(ErrorKind::InvalidOperation, "Could not serialize argument")
                        .with_source(e)
                })?;

                Ok::<_, Error>(Argument::named(name.to_owned(), value))
            })
            .collect();
        let list = res?;

        let formatted = message.format_(&list).map_err(|e| {
            Error::new(ErrorKind::InvalidOperation, "Could not format message").with_source(e)
        })?;

        let mut buf = String::with_capacity(formatted.len());
        let mut output = make_string_output(&mut buf);
        for part in formatted.parts() {
            match part {
                FormattedMessagePart::Text(text) => {
                    // Literal text, just write it
                    output.write_str(text)?;
                }
                FormattedMessagePart::Placeholder(placeholder) => {
                    // Placeholder, escape it
                    escape_formatter(&mut output, state, &placeholder.as_str().into())?;
                }
            }
        }

        Ok(Value::from_safe_string(buf))
    }

    fn call_method(
        self: &Arc<Self>,
        _state: &State,
        name: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
        match name {
            "relative_date" => {
                let (date,): (String,) = from_args(args)?;
                let date: chrono::DateTime<chrono::Utc> = date.parse().map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidOperation,
                        "Invalid date while calling function `relative_date`",
                    )
                    .with_source(e)
                })?;

                // TODO: grab the clock somewhere
                #[allow(clippy::disallowed_methods)]
                let now = chrono::Utc::now();

                let diff = (date - now).num_days();

                Ok(Value::from(
                    self.translator
                        .relative_date(&self.lang, diff)
                        .map_err(|_e| {
                            Error::new(
                                ErrorKind::InvalidOperation,
                                "Failed to format relative date",
                            )
                        })?,
                ))
            }

            "short_time" => {
                let (date,): (String,) = from_args(args)?;
                let date: chrono::DateTime<chrono::Utc> = date.parse().map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidOperation,
                        "Invalid date while calling function `time`",
                    )
                    .with_source(e)
                })?;

                // TODO: we should use the user's timezone here
                let time = date.time();

                Ok(Value::from(
                    self.translator
                        .short_time(&self.lang, &TimeAdapter(time))
                        .map_err(|_e| {
                            Error::new(ErrorKind::InvalidOperation, "Failed to format time")
                        })?,
                ))
            }

            _ => Err(Error::new(
                ErrorKind::InvalidOperation,
                "Invalid method on include_asset",
            )),
        }
    }
}

/// An adapter to make a [`Timelike`] implement [`IsoTimeInput`]
///
/// [`Timelike`]: chrono::Timelike
/// [`IsoTimeInput`]: mas_i18n::icu_datetime::input::IsoTimeInput
struct TimeAdapter<T>(T);

impl<T: chrono::Timelike> mas_i18n::icu_datetime::input::IsoTimeInput for TimeAdapter<T> {
    fn hour(&self) -> Option<mas_i18n::icu_calendar::types::IsoHour> {
        let hour: usize = chrono::Timelike::hour(&self.0).try_into().ok()?;
        hour.try_into().ok()
    }

    fn minute(&self) -> Option<mas_i18n::icu_calendar::types::IsoMinute> {
        let minute: usize = chrono::Timelike::minute(&self.0).try_into().ok()?;
        minute.try_into().ok()
    }

    fn second(&self) -> Option<mas_i18n::icu_calendar::types::IsoSecond> {
        let second: usize = chrono::Timelike::second(&self.0).try_into().ok()?;
        second.try_into().ok()
    }

    fn nanosecond(&self) -> Option<mas_i18n::icu_calendar::types::NanoSecond> {
        let nanosecond: usize = chrono::Timelike::nanosecond(&self.0).try_into().ok()?;
        nanosecond.try_into().ok()
    }
}

struct IncludeAsset {
    url_builder: UrlBuilder,
    vite_manifest: ViteManifest,
}

impl std::fmt::Debug for IncludeAsset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncludeAsset")
            .field("url_builder", &self.url_builder.assets_base())
            .field("vite_manifest", &"..")
            .finish()
    }
}

impl std::fmt::Display for IncludeAsset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("include_asset")
    }
}

impl Object for IncludeAsset {
    fn call(self: &Arc<Self>, _state: &State, args: &[Value]) -> Result<Value, Error> {
        let (path,): (&str,) = from_args(args)?;

        let path: &Utf8Path = path.into();

        let (main, imported) = self.vite_manifest.find_assets(path).map_err(|e| {
            Error::new(
                ErrorKind::InvalidOperation,
                format!("Invalid assets manifest while calling function `include_asset` with path = {path:?}: {e}"),
            )
        })?;

        let assets = std::iter::once(main)
            .chain(imported.iter().filter(|a| a.is_stylesheet()).copied())
            .filter_map(|asset| asset.include_tag(self.url_builder.assets_base().into()));

        let preloads = imported
            .iter()
            .filter(|a| a.is_script())
            .map(|asset| asset.preload_tag(self.url_builder.assets_base().into()));

        let tags: Vec<String> = preloads.chain(assets).collect();

        Ok(Value::from_safe_string(tags.join("\n")))
    }
}

struct FakeIncludeAsset {}

impl std::fmt::Debug for FakeIncludeAsset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeIncludeAsset").finish()
    }
}

impl std::fmt::Display for FakeIncludeAsset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fake_include_asset")
    }
}

impl Object for FakeIncludeAsset {
    fn call(self: &Arc<Self>, _state: &State, args: &[Value]) -> Result<Value, Error> {
        let (path,): (&str,) = from_args(args)?;

        Ok(Value::from_safe_string(format!(
            "<!--- include_asset {path} -->"
        )))
    }
}

#[derive(Debug, Default)]
struct Counter {
    count: AtomicUsize,
}

impl std::fmt::Display for Counter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.count.load(std::sync::atomic::Ordering::Relaxed)
        )
    }
}

impl Object for Counter {
    fn call_method(
        self: &Arc<Self>,
        _state: &State,
        name: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
        // None of the methods take any arguments
        from_args::<()>(args)?;

        match name {
            "reset" => {
                self.count.store(0, std::sync::atomic::Ordering::Relaxed);
                Ok(Value::UNDEFINED)
            }
            "next" => {
                let old = self
                    .count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(Value::from(old))
            }
            "peek" => Ok(Value::from(
                self.count.load(std::sync::atomic::Ordering::Relaxed),
            )),
            _ => Err(Error::new(
                ErrorKind::InvalidOperation,
                "Invalid method on counter",
            )),
        }
    }
}
