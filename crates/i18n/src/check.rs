// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Validation that downloaded translations match the English source.
//!
//! Translations are authored in `translations/en.json` and translated by an
//! external service (Localazy), landing as `translations/<lang>.json`. The
//! server-side template renderer treats the *literal text* of a translation,
//! including any HTML tags it contains, as trusted raw HTML. A translated
//! string that introduces new markup, alters an attribute (e.g. an `href`), or
//! drops/renames a placeholder is therefore both a correctness bug and a
//! potential HTML-injection vector.
//!
//! [`check_translations`] checks that, for every key present in both the source
//! and a translated file, the translated string has exactly the same set of
//! sprintf placeholders and HTML tags (with their attributes) as the source. It
//! is used both by the `mas-cli templates check` command and by an in-tree test
//! against the committed translations.
//!
//! HTML is tokenized with the spec-compliant [`html5gum`] and tags are compared
//! by their verbatim source text, so the check is strict: a reordered
//! attribute, a changed quote, or extra whitespace inside a tag all count as a
//! mismatch (their order *within* the string does not, as translators reorder
//! tags). Anything that is not a plain string or a start/end tag — an HTML
//! comment, a doctype, or a tokenizer error (a literal `<`/`>` that should be
//! HTML-encoded as `&lt;`/`&gt;`, or an unterminated tag) — is rejected
//! outright.
//!
//! The walk is over the raw [`serde_json::Value`] rather than the typed
//! [`TranslationTree`](crate::translations): that loader fails hard on the
//! first malformed leaf and discards `@`-metadata and unknown keys, whereas the
//! validator must survive malformed input to report an issue per key.

use std::{collections::BTreeSet, fmt};

use camino::{Utf8Path, Utf8PathBuf};
use serde_json::Value;
use thiserror::Error;

use crate::{
    Message,
    translations::{PLURAL_CATEGORIES, plural_category_as_str},
};

/// The set of canonical placeholder tokens (e.g. `%(name)s`, `%2$d`) of a
/// parsed message, identified with the real sprintf parser.
fn placeholder_set(message: &Message) -> BTreeSet<String> {
    message.placeholders().map(ToString::to_string).collect()
}

/// A construct that must never appear in a translation. The translation text is
/// rendered as raw HTML, so anything beyond plain text and matching start/end
/// tags is rejected outright.
#[derive(Debug, Error)]
enum MarkupError {
    #[error("contains an HTML comment")]
    Comment,
    #[error("contains a doctype declaration")]
    Doctype,
    /// A tokenizer error: an unencoded `<`/`>` (which must be written `&lt;`/
    /// `&gt;`), an unterminated tag, or otherwise malformed markup.
    #[error("contains invalid markup (an unencoded `<`/`>`, or an unterminated tag): {code}")]
    Invalid { code: &'static str },
}

/// The set of HTML tags in a raw message string, each as its verbatim source
/// text so the comparison is exact — a reordered attribute or changed quoting
/// is a different tag — while their order within the string does not matter.
///
/// Returns [`MarkupError`] on the first comment, doctype or tokenizer error, so
/// those fail the check. The tokenizer ([`html5gum`]) is spec-compliant, so we
/// do not parse HTML ourselves.
fn markup_set(input: &str) -> Result<BTreeSet<&str>, MarkupError> {
    html5gum::Tokenizer::new_with_emitter(input, html5gum::DefaultEmitter::<usize>::new_with_span())
        .map(|result| match result {
            Ok(token) => token,
            // The reader is a `&str`, so tokenization is infallible.
            Err(error) => match error {},
        })
        .filter_map(|token| match token {
            html5gum::Token::StartTag(tag) => Some(Ok(&input[tag.span.start..tag.span.end])),
            html5gum::Token::EndTag(tag) => Some(Ok(&input[tag.span.start..tag.span.end])),
            html5gum::Token::String(_) => None,
            html5gum::Token::Comment(_) => Some(Err(MarkupError::Comment)),
            html5gum::Token::Doctype(_) => Some(Err(MarkupError::Doctype)),
            html5gum::Token::Error(error) => Some(Err(MarkupError::Invalid {
                code: error.value.as_str(),
            })),
        })
        .collect()
}

/// Set difference in both directions, returning `Some((missing, unexpected))`
/// only when the sets differ. `missing` are in `source` but not `translated`;
/// `unexpected` are in `translated` but not `source`.
fn set_diff<T: Ord + ToString>(
    source: &BTreeSet<T>,
    translated: &BTreeSet<T>,
) -> Option<(Vec<String>, Vec<String>)> {
    let missing: Vec<String> = source
        .difference(translated)
        .map(ToString::to_string)
        .collect();
    let unexpected: Vec<String> = translated
        .difference(source)
        .map(ToString::to_string)
        .collect();
    if missing.is_empty() && unexpected.is_empty() {
        None
    } else {
        Some((missing, unexpected))
    }
}

/// A single problem found when comparing a translated string to its source.
#[derive(Debug)]
enum Violation {
    /// The translated string is not a valid sprintf message.
    Unparseable(String),
    /// The set of placeholders differs from the source.
    Placeholders {
        missing: Vec<String>,
        unexpected: Vec<String>,
    },
    /// The set of HTML tags/attributes differs from the source.
    Markup {
        missing: Vec<String>,
        unexpected: Vec<String>,
    },
    /// The translation contains markup that is never allowed (a comment,
    /// doctype, or unencoded/malformed markup).
    ForbiddenMarkup(MarkupError),
    /// The source and translation are different JSON shapes (e.g. one is a
    /// plural object and the other a plain string).
    Structure,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, missing, unexpected) = match self {
            Violation::Unparseable(detail) => {
                return write!(f, "translated string is not a valid message: {detail}");
            }
            Violation::ForbiddenMarkup(error) => return write!(f, "forbidden markup: {error}"),
            Violation::Structure => {
                return write!(f, "unexpected JSON shape (expected a translation string)");
            }
            Violation::Placeholders {
                missing,
                unexpected,
            } => ("placeholder", missing, unexpected),
            Violation::Markup {
                missing,
                unexpected,
            } => ("markup", missing, unexpected),
        };
        // Tags contain spaces, so quote each token and separate with commas to
        // keep a multi-item diff unambiguous.
        write!(f, "{kind} mismatch:")?;
        if !missing.is_empty() {
            write!(f, " missing {}", quote_join(missing))?;
        }
        if !unexpected.is_empty() {
            write!(f, " unexpected {}", quote_join(unexpected))?;
        }
        Ok(())
    }
}

/// Join tokens for display as `` `a`, `b` ``.
fn quote_join(items: &[String]) -> String {
    items
        .iter()
        .map(|item| format!("`{item}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Compare a single translated string against its source string.
fn compare_message(source: &str, translated: &str) -> Vec<Violation> {
    let mut violations = Vec::new();

    match (markup_set(source), markup_set(translated)) {
        (Ok(source_tags), Ok(translated_tags)) => {
            if let Some((missing, unexpected)) = set_diff(&source_tags, &translated_tags) {
                violations.push(Violation::Markup {
                    missing,
                    unexpected,
                });
            }
        }
        // Forbidden markup in the translation. The source is trusted, so an
        // error on the source side is ignored here.
        (_, Err(error)) => violations.push(Violation::ForbiddenMarkup(error)),
        (Err(_), Ok(_)) => {}
    }

    // The placeholder comparison needs both strings to parse.
    match (source.parse::<Message>(), translated.parse::<Message>()) {
        (Ok(source_message), Ok(translated_message)) => {
            if let Some((missing, unexpected)) = set_diff(
                &placeholder_set(&source_message),
                &placeholder_set(&translated_message),
            ) {
                violations.push(Violation::Placeholders {
                    missing,
                    unexpected,
                });
            }
        }
        // The source parses but the translation does not: definitely broken.
        (Ok(_), Err(error)) => violations.push(Violation::Unparseable(error.to_string())),
        // An unparseable source cannot happen for committed files (the runtime
        // rejects them on load); `english_source_is_valid` asserts it
        // separately, so we do not blame the translation for it here.
        (Err(_), _) => {}
    }

    violations
}

/// Whether a key is the name of a CLDR plural category.
fn is_plural_category(key: &str) -> bool {
    PLURAL_CATEGORIES
        .into_iter()
        .map(plural_category_as_str)
        .any(|name| name == key)
}

/// Whether every (non-metadata) key of an object is a CLDR plural category with
/// a string value; otherwise it is a nested namespace that merely happens to
/// reuse a category-like name for a subtree.
fn is_plural(object: &serde_json::Map<String, Value>) -> bool {
    let mut saw_category = false;
    for (key, value) in object {
        if key.starts_with('@') {
            continue;
        }
        if !is_plural_category(key) || !value.is_string() {
            return false;
        }
        saw_category = true;
    }
    saw_category
}

/// Pick a source string from a plural object to compare against a translated
/// category the source itself lacks: prefer `other`, then `one`, then any.
fn plural_reference(object: &serde_json::Map<String, Value>) -> Option<&str> {
    for preferred in ["other", "one"] {
        if let Some(Value::String(value)) = object.get(preferred) {
            return Some(value);
        }
    }
    object
        .iter()
        .find(|(key, _)| !key.starts_with('@'))
        .and_then(|(_, value)| value.as_str())
}

fn join_key(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

/// Recursively walk the source and translated trees in parallel, collecting
/// violations keyed by their dot-separated path and any keys present in the
/// translation but absent from the source.
fn walk(
    path: &str,
    source: &Value,
    translated: &Value,
    violations: &mut Vec<(String, Violation)>,
    extra_keys: &mut Vec<String>,
) {
    match (source, translated) {
        (Value::String(source), Value::String(translated)) => {
            for violation in compare_message(source, translated) {
                violations.push((path.to_owned(), violation));
            }
        }
        (Value::Object(source_map), Value::Object(translated_map)) => {
            if is_plural(source_map) {
                for (category, value) in translated_map {
                    if category.starts_with('@') {
                        continue;
                    }
                    // The runtime only ever looks up a real CLDR category (or
                    // `other`), so a stray non-category key is dead data — treat
                    // it like any other translation-only key rather than
                    // comparing it against a reference and failing spuriously.
                    if !is_plural_category(category) {
                        extra_keys.push(join_key(path, category));
                        continue;
                    }
                    let Value::String(value) = value else {
                        // A plural category must map to a string; any other
                        // shape is a structural mismatch (and the runtime
                        // loader would reject the file outright).
                        violations.push((join_key(path, category), Violation::Structure));
                        continue;
                    };
                    // Compare against the source's *same* category when it has
                    // one (a source `one` and `other` legitimately differ), and
                    // only fall back to a reference for categories the source
                    // lacks (target locales have more categories than English).
                    let reference = source_map
                        .get(category)
                        .and_then(Value::as_str)
                        .or_else(|| plural_reference(source_map));
                    if let Some(reference) = reference {
                        for violation in compare_message(reference, value) {
                            violations.push((join_key(path, category), violation));
                        }
                    }
                }
            } else {
                for (key, source_child) in source_map {
                    if key.starts_with('@') {
                        continue;
                    }
                    // Missing keys are fine: the runtime falls back to English.
                    if let Some(translated_child) = translated_map.get(key) {
                        walk(
                            &join_key(path, key),
                            source_child,
                            translated_child,
                            violations,
                            extra_keys,
                        );
                    }
                }
                for key in translated_map.keys() {
                    if key.starts_with('@') || source_map.contains_key(key) {
                        continue;
                    }
                    // Translation-only keys are never looked up at runtime; the
                    // loader (`Translator::load_from_path`) is what enforces
                    // that they still parse, so here they are only recorded.
                    extra_keys.push(join_key(path, key));
                }
            }
        }
        _ => violations.push((path.to_owned(), Violation::Structure)),
    }
}

/// A single mismatch between a translated string and the English source, or a
/// translation file that could not be read.
#[derive(Debug, Clone)]
pub struct TranslationIssue {
    /// The locale of the offending translation, i.e. the file stem (`fr`).
    pub locale: String,
    /// The dot-separated key path, or empty for a file-level problem.
    pub key: String,
    /// A human-readable description of the problem.
    pub detail: String,
}

impl fmt::Display for TranslationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.key.is_empty() {
            write!(f, "{}.json: {}", self.locale, self.detail)
        } else {
            write!(f, "{}.json: {}: {}", self.locale, self.key, self.detail)
        }
    }
}

/// The outcome of [`check_translations`].
#[derive(Debug, Default)]
pub struct CheckReport {
    /// Placeholder/markup mismatches, unparseable messages and unreadable or
    /// invalid files. Because markup is rendered as trusted HTML, any of these
    /// should fail a build.
    pub issues: Vec<TranslationIssue>,
    /// Keys present in a translation but absent from the source. These are
    /// harmless at runtime (they are never looked up) but worth cleaning up.
    pub unknown_keys: Vec<TranslationIssue>,
}

impl CheckReport {
    /// Whether the check found any hard [`issues`](Self::issues) (unknown keys
    /// are only warnings and do not count).
    #[must_use]
    pub fn has_issues(&self) -> bool {
        !self.issues.is_empty()
    }
}

/// An error that prevents the translation check from running at all.
#[derive(Debug, Error)]
pub enum CheckError {
    /// The translations directory could not be listed.
    #[error("could not read translations directory `{path}`")]
    ReadDir {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The English source file could not be read.
    #[error("could not read the English source `{path}`")]
    ReadSource {
        path: Utf8PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The English source file is not valid JSON.
    #[error("the English source `{path}` is not valid JSON")]
    ParseSource {
        path: Utf8PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Check every `<locale>.json` in `dir` against the English source `en.json`.
///
/// For every key present in both, the translated string must have the same set
/// of sprintf placeholders and HTML tags (with attributes) as the source; see
/// the [module docs](self) for why this matters for security. Keys missing from
/// a translation are ignored (the runtime falls back to English); keys present
/// only in a translation are reported as
/// [`unknown_keys`](CheckReport::unknown_keys).
///
/// # Errors
///
/// Returns [`CheckError`] if the directory cannot be listed or the English
/// source cannot be read or parsed. Problems with individual translation files
/// (unreadable, invalid JSON, mismatched) are collected into the returned
/// [`CheckReport`] rather than returned as errors.
pub fn check_translations(dir: &Utf8Path) -> Result<CheckReport, CheckError> {
    let source_path = dir.join("en.json");
    let source_text =
        std::fs::read_to_string(&source_path).map_err(|error| CheckError::ReadSource {
            path: source_path.clone(),
            source: error,
        })?;
    let source: Value =
        serde_json::from_str(&source_text).map_err(|error| CheckError::ParseSource {
            path: source_path.clone(),
            source: error,
        })?;

    let read_dir = std::fs::read_dir(dir).map_err(|error| CheckError::ReadDir {
        path: dir.to_owned(),
        source: error,
    })?;
    let mut paths: Vec<Utf8PathBuf> = read_dir
        .filter_map(Result::ok)
        .filter_map(|entry| Utf8PathBuf::from_path_buf(entry.path()).ok())
        .filter(|path| path.extension() == Some("json") && path.file_stem() != Some("en"))
        .collect();
    paths.sort();

    let mut report = CheckReport::default();
    for path in paths {
        let locale = path.file_stem().unwrap_or_default().to_owned();

        let translated = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<Value>(&text)
                .map_err(|error| format!("not valid JSON: {error}")),
            Err(error) => Err(format!("could not read file: {error}")),
        };
        let translated = match translated {
            Ok(value) => value,
            Err(detail) => {
                report.issues.push(TranslationIssue {
                    locale,
                    key: String::new(),
                    detail,
                });
                continue;
            }
        };

        let mut violations = Vec::new();
        let mut extra_keys = Vec::new();
        walk("", &source, &translated, &mut violations, &mut extra_keys);

        for (key, violation) in violations {
            report.issues.push(TranslationIssue {
                locale: locale.clone(),
                key,
                detail: violation.to_string(),
            });
        }
        for key in extra_keys {
            report.unknown_keys.push(TranslationIssue {
                locale: locale.clone(),
                key,
                detail: "key not present in en.json".to_owned(),
            });
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Translator;

    fn parse(source: &str) -> Value {
        serde_json::from_str(source).expect("valid JSON")
    }

    /// Assert that comparing `translated` against `source` yields at least one
    /// violation matching `want`.
    fn assert_violation(source: &str, translated: &str, want: fn(&Violation) -> bool) {
        let violations = compare_message(source, translated);
        assert!(violations.iter().any(want), "{violations:?}");
    }

    /// Assert that `translated` matches `source` with no violations.
    fn assert_clean(source: &str, translated: &str) {
        let violations = compare_message(source, translated);
        assert!(violations.is_empty(), "{violations:?}");
    }

    fn is_placeholders(violation: &Violation) -> bool {
        matches!(violation, Violation::Placeholders { .. })
    }
    fn is_markup(violation: &Violation) -> bool {
        matches!(violation, Violation::Markup { .. })
    }
    fn is_forbidden(violation: &Violation) -> bool {
        matches!(violation, Violation::ForbiddenMarkup(_))
    }

    // --- Pure-function tests: placeholders --------------------------------

    #[test]
    fn identical_strings_pass() {
        assert_clean("Hello %(name)s", "Bonjour %(name)s");
    }

    #[test]
    fn missing_placeholder_fails() {
        assert_violation("Hello %(name)s", "Bonjour", is_placeholders);
    }

    #[test]
    fn renamed_placeholder_fails() {
        assert_violation("Hello %(name)s", "Bonjour %(nom)s", is_placeholders);
    }

    #[test]
    fn added_placeholder_fails() {
        assert_violation("Hello", "Bonjour %(name)s", is_placeholders);
    }

    #[test]
    fn reordered_named_placeholders_pass() {
        assert_clean("%(a)s then %(b)s", "%(b)s puis %(a)s");
    }

    #[test]
    fn changed_type_specifier_fails() {
        assert_violation("%(count)d items", "%(count)s objets", is_placeholders);
    }

    #[test]
    fn unparseable_translation_fails() {
        assert_violation("Hello", "Bonjour %(", |v| {
            matches!(v, Violation::Unparseable(_))
        });
    }

    // --- Pure-function tests: markup --------------------------------------

    #[test]
    fn changed_href_fails() {
        assert_violation(
            r#"<a href="%s" class="cpd-link">Terms</a>"#,
            r#"<a href="evil" class="cpd-link">Conditions</a>"#,
            is_markup,
        );
    }

    #[test]
    fn injected_script_fails() {
        assert_violation(
            "Enter code <strong>%(code)s</strong>",
            "Entrez le code <strong>%(code)s</strong><script>alert(1)</script>",
            is_markup,
        );
    }

    #[test]
    fn removed_closing_tag_fails() {
        assert_violation("<span>%(name)s</span>", "<span>%(name)s", is_markup);
    }

    #[test]
    fn reordered_tags_pass() {
        assert_clean(
            "<em>%(a)s</em> and <strong>%(b)s</strong>",
            "<strong>%(b)s</strong> et <em>%(a)s</em>",
        );
    }

    #[test]
    fn identical_self_closing_tags_pass() {
        assert_clean("a<br/>b", "c<br/>d");
    }

    #[test]
    fn reordered_attributes_fail() {
        // The comparison is on verbatim tag text, so attribute order must match.
        assert_violation(
            r#"<a href="%s" class="cpd-link">x</a>"#,
            r#"<a class="cpd-link" href="%s">y</a>"#,
            is_markup,
        );
    }

    // --- Adversarial: tokenizer must fail closed --------------------------

    #[test]
    fn unterminated_tag_against_plain_source_fails() {
        // Source has no markup; the translation appends an unterminated tag the
        // surrounding page would close.
        assert_violation("Hello", "Bonjour <img src=x onerror=alert(1)", is_forbidden);
    }

    #[test]
    fn unterminated_tag_mirroring_source_fails() {
        assert_violation(
            "<strong>%(code)s</strong>",
            "<strong>%(code)s</strong> texte <svg onload=alert(1)",
            is_forbidden,
        );
    }

    #[test]
    fn quoted_gt_attribute_desync_fails() {
        // `>` inside the quoted `class` value must not end the tag early and let
        // an extra `onmouseover` handler slip past.
        assert_violation(
            r#"<a href="%s" class="cpd-link">Terms</a>"#,
            r#"<a href="%s" class="cpd-link>" onmouseover="alert(1)">Conditions</a>"#,
            is_markup,
        );
    }

    #[test]
    fn empty_attribute_name_fails() {
        // A stray leading `=` is a tokenizer error, so the whole tag is rejected.
        assert_violation(
            r#"<a href="%s">T</a>"#,
            r#"<a =onmouseover=alert(1) href="%s">C</a>"#,
            is_forbidden,
        );
    }

    #[test]
    fn injected_comment_fails() {
        assert_violation("<em>%(x)s</em>", "<em>%(x)s</em><!-- sneaky -->", |v| {
            matches!(v, Violation::ForbiddenMarkup(MarkupError::Comment))
        });
    }

    #[test]
    fn injected_doctype_fails() {
        assert_violation("Hello", "<!doctype html>Bonjour", |v| {
            matches!(v, Violation::ForbiddenMarkup(MarkupError::Doctype))
        });
    }

    #[test]
    fn literal_angle_bracket_must_be_encoded() {
        // A literal `<`/`>` must be HTML-encoded as `&lt;`/`&gt;` (translation
        // text is rendered as raw HTML).
        assert_violation("2 &lt; 3", "2 < 3", |v| {
            matches!(v, Violation::ForbiddenMarkup(MarkupError::Invalid { .. }))
        });
    }

    #[test]
    fn encoded_angle_brackets_pass() {
        assert_clean("2 &lt; 3 &gt; 1", "2 &lt; 3 &gt; 1");
    }

    #[test]
    fn unparseable_source_still_checks_markup() {
        // A bare `%` makes the sprintf parse fail; markup must still be checked.
        assert_violation(
            "100% <em>safe</em>",
            "100% <em>safe</em><script>x</script>",
            is_markup,
        );
    }

    #[test]
    fn unparseable_source_matching_markup_passes() {
        assert_clean("100% <em>safe</em>", "100% <em>sûr</em>");
    }

    // --- Tree walking -----------------------------------------------------

    fn walk_all(source: &Value, translated: &Value) -> Vec<(String, Violation)> {
        let mut violations = Vec::new();
        let mut extra = Vec::new();
        walk("", source, translated, &mut violations, &mut extra);
        violations
    }

    fn walk_extra(source: &Value, translated: &Value) -> Vec<String> {
        let mut violations = Vec::new();
        let mut extra = Vec::new();
        walk("", source, translated, &mut violations, &mut extra);
        extra
    }

    #[test]
    fn missing_key_is_skipped() {
        let source = parse(r#"{ "greeting": "Hello %(name)s", "farewell": "Bye" }"#);
        let translated = parse(r#"{ "greeting": "Bonjour %(name)s" }"#);
        assert!(walk_all(&source, &translated).is_empty());
    }

    #[test]
    fn nested_mismatch_is_reported_with_path() {
        let source = parse(r#"{ "a": { "b": "Hello %(name)s" } }"#);
        let translated = parse(r#"{ "a": { "b": "Bonjour" } }"#);
        let violations = walk_all(&source, &translated);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "a.b");
    }

    #[test]
    fn metadata_keys_are_ignored() {
        let source = parse(r#"{ "greeting": "Hello %(name)s", "@greeting": { "context": "x" } }"#);
        let translated = parse(r#"{ "greeting": "Bonjour %(name)s" }"#);
        assert!(walk_all(&source, &translated).is_empty());
    }

    #[test]
    fn matching_plural_passes() {
        let source = parse(
            r#"{ "sessions": { "one": "%(count)d session", "other": "%(count)d sessions" } }"#,
        );
        let translated = parse(
            r#"{ "sessions": { "one": "%(count)d session", "few": "%(count)d sessions", "many": "%(count)d sessions", "other": "%(count)d sessions" } }"#,
        );
        assert!(walk_all(&source, &translated).is_empty());
    }

    #[test]
    fn plural_with_broken_variant_fails() {
        let source = parse(r#"{ "sessions": { "other": "%(count)d sessions" } }"#);
        let translated = parse(r#"{ "sessions": { "other": "sessions" } }"#);
        let violations = walk_all(&source, &translated);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "sessions.other");
    }

    #[test]
    fn plural_categories_compared_pairwise() {
        // The source `one` has no placeholder but `other` does; a correct
        // translation must be compared category-against-category, not every
        // category against `other`.
        let source =
            parse(r#"{ "sessions": { "one": "one session", "other": "%(count)d sessions" } }"#);
        let translated =
            parse(r#"{ "sessions": { "one": "une session", "other": "%(count)d sessions" } }"#);
        assert!(walk_all(&source, &translated).is_empty());
    }

    #[test]
    fn category_named_namespace_is_not_a_plural() {
        // A namespace whose keys happen to be category names but hold objects is
        // recursed into, not treated as a plural.
        let source = parse(r#"{ "other": { "greeting": "Hello %(name)s" } }"#);
        let translated = parse(r#"{ "other": { "greeting": "Bonjour" } }"#);
        let violations = walk_all(&source, &translated);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "other.greeting");
    }

    #[test]
    fn string_vs_object_is_structure() {
        let source = parse(r#"{ "a": "hello" }"#);
        let translated = parse(r#"{ "a": { "b": "hello" } }"#);
        let violations = walk_all(&source, &translated);
        assert!(matches!(violations[..], [(_, Violation::Structure)]));
        assert_eq!(violations[0].0, "a");
    }

    #[test]
    fn plural_category_with_non_string_value_is_structure() {
        // A plural category must map to a string; an object there is a
        // structural mismatch the runtime loader would also reject.
        let source = parse(r#"{ "n": { "other": "%(count)d items" } }"#);
        let translated = parse(r#"{ "n": { "other": { "deep": "x" } } }"#);
        let violations = walk_all(&source, &translated);
        assert!(matches!(violations[..], [(_, Violation::Structure)]));
        assert_eq!(violations[0].0, "n.other");
    }

    #[test]
    fn non_category_key_in_plural_is_an_unknown_key() {
        // A stray non-category key inside a plural object is never looked up, so
        // it is an unknown key, not a spurious hard failure.
        let source = parse(r#"{ "n": { "other": "%(count)d items" } }"#);
        let translated =
            parse(r#"{ "n": { "other": "%(count)d objets", "misc": "no placeholder" } }"#);
        assert!(walk_all(&source, &translated).is_empty());
        assert_eq!(walk_extra(&source, &translated), vec!["n.misc".to_owned()]);
    }

    #[test]
    fn extra_key_is_recorded_as_unknown() {
        let source = parse(r#"{ "a": "x" }"#);
        let translated = parse(r#"{ "a": "y", "b": "z" }"#);
        assert!(walk_all(&source, &translated).is_empty());
        assert_eq!(walk_extra(&source, &translated), vec!["b".to_owned()]);
    }

    // --- The real committed translation files -----------------------------

    fn translations_dir() -> Utf8PathBuf {
        Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../translations")
            .canonicalize_utf8()
            .expect("translations directory should exist")
    }

    /// Visit every leaf value (non-`@` keys only) with its dot-joined path.
    fn for_each_leaf(path: &str, value: &Value, f: &mut impl FnMut(&str, &Value)) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    if !key.starts_with('@') {
                        for_each_leaf(&join_key(path, key), child, f);
                    }
                }
            }
            _ => f(path, value),
        }
    }

    /// Assert every leaf string in `en.json` is a valid sprintf message with
    /// well-formed markup. [`check_translations`] trusts the source side: an
    /// unparseable or malformed source string silently stops the comparison
    /// covering the affected key, so the source itself is validated here.
    #[test]
    fn english_source_is_valid() {
        let source: Value = serde_json::from_str(
            &std::fs::read_to_string(translations_dir().join("en.json"))
                .expect("en.json should be readable"),
        )
        .expect("en.json should be valid JSON");

        let mut bad = Vec::new();
        for_each_leaf("", &source, &mut |path, value| {
            let Value::String(text) = value else { return };
            if let Err(error) = text.parse::<Message>() {
                bad.push(format!("  {path}: not a valid sprintf message: {error}"));
            }
            if let Err(error) = markup_set(text) {
                bad.push(format!("  {path}: {error}"));
            }
        });
        assert!(
            bad.is_empty(),
            "translations/en.json has invalid strings:\n{}",
            bad.join("\n")
        );
    }

    /// Loadability of every committed file — including translation-only keys,
    /// which the checker no longer validates — is enforced by the runtime
    /// loader, so exercise it here.
    #[test]
    fn committed_translations_load() {
        Translator::load_from_path(&translations_dir())
            .expect("all committed translation files should load");
    }

    #[test]
    fn committed_translations_match_source() {
        let report =
            check_translations(&translations_dir()).expect("translations should be checkable");

        if !report.unknown_keys.is_empty() {
            // Extra keys have no runtime effect (they are never looked up), so
            // they are surfaced as a warning rather than a failure.
            let warnings: Vec<String> = report
                .unknown_keys
                .iter()
                .map(ToString::to_string)
                .collect();
            eprintln!(
                "Translation keys not present in en.json (ignored):\n{}",
                warnings.join("\n")
            );
        }

        assert!(
            !report.has_issues(),
            "Translated strings disagree with translations/en.json on placeholders or markup.\n\
             Markup is rendered as trusted HTML, so these must match exactly.\n{}",
            report
                .issues
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
