// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashMap, hash::Hash};

use serde::{Deserialize, Serialize};

/// A trait which should be used for form field enums
pub trait FormField: Copy + Hash + PartialEq + Eq + Serialize + for<'de> Deserialize<'de> {
    /// Return false for fields where values should not be kept (e.g. password
    /// fields)
    fn keep(&self) -> bool;
}

/// An error on a form field
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FieldError {
    /// A required field is missing
    Required,

    /// An unspecified error on the field
    Unspecified,

    /// Invalid value for this field
    Invalid,

    /// The password confirmation doesn't match the password
    PasswordMismatch,

    /// That value already exists
    Exists,

    /// Denied by the policy
    Policy {
        /// Well-known policy code
        code: Option<&'static str>,

        /// Message for this policy violation
        message: String,
    },
}

/// An error on the whole form
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FormError {
    /// The given credentials are not valid
    InvalidCredentials,

    /// Password fields don't match
    PasswordMismatch,

    /// There was an internal error
    Internal,

    /// Rate limit exceeded
    RateLimitExceeded,

    /// Denied by the policy
    Policy {
        /// Well-known policy code
        code: Option<&'static str>,

        /// Message for this policy violation
        message: String,
    },

    /// Failed to validate CAPTCHA
    Captcha,
}

#[derive(Debug, Default, Serialize)]
struct FieldState {
    value: Option<String>,
    errors: Vec<FieldError>,
}

/// The state of a form and its fields
#[derive(Debug, Serialize)]
pub struct FormState<K: Hash + Eq> {
    fields: HashMap<K, FieldState>,
    errors: Vec<FormError>,

    #[serde(skip)]
    has_errors: bool,
}

impl<K: Hash + Eq> Default for FormState<K> {
    fn default() -> Self {
        FormState {
            fields: HashMap::default(),
            errors: Vec::default(),
            has_errors: false,
        }
    }
}

#[derive(Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
enum KeyOrOther<K> {
    Key(K),
    Other(String),
}

impl<K> KeyOrOther<K> {
    fn key(self) -> Option<K> {
        match self {
            Self::Key(key) => Some(key),
            Self::Other(_) => None,
        }
    }
}

impl<K: FormField> FormState<K> {
    /// Generate a [`FormState`] out of a form
    ///
    /// # Panics
    ///
    /// If the form fails to serialize, or the form field keys fail to
    /// deserialize
    pub fn from_form<F: Serialize>(form: &F) -> Self {
        let form = serde_json::to_value(form).unwrap();
        let fields: HashMap<KeyOrOther<K>, Option<String>> = serde_json::from_value(form).unwrap();

        let fields = fields
            .into_iter()
            .filter_map(|(key, value)| {
                let key = key.key()?;
                let value = key.keep().then_some(value).flatten();
                let field = FieldState {
                    value,
                    errors: Vec::new(),
                };
                Some((key, field))
            })
            .collect();

        FormState {
            fields,
            errors: Vec::new(),
            has_errors: false,
        }
    }

    /// Add an error on a form field
    pub fn add_error_on_field(&mut self, field: K, error: FieldError) {
        self.fields.entry(field).or_default().errors.push(error);
        self.has_errors = true;
    }

    /// Add an error on a form field
    #[must_use]
    pub fn with_error_on_field(mut self, field: K, error: FieldError) -> Self {
        self.add_error_on_field(field, error);
        self
    }

    /// Add an error on the form
    pub fn add_error_on_form(&mut self, error: FormError) {
        self.errors.push(error);
        self.has_errors = true;
    }

    /// Add an error on the form
    #[must_use]
    pub fn with_error_on_form(mut self, error: FormError) -> Self {
        self.add_error_on_form(error);
        self
    }

    /// Set a value on the form
    pub fn set_value(&mut self, field: K, value: Option<String>) {
        self.fields.entry(field).or_default().value = value;
    }

    /// Checks if a field contains a value
    pub fn has_value(&self, field: K) -> bool {
        self.fields.get(&field).is_some_and(|f| f.value.is_some())
    }

    /// Returns `true` if the form has no error attached to it
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.has_errors
    }
}

/// Utility trait to help creating [`FormState`] out of a form
pub trait ToFormState: Serialize {
    /// The enum used for field names
    type Field: FormField;

    /// Generate a [`FormState`] out of [`Self`]
    ///
    /// # Panics
    ///
    /// If the form fails to serialize or [`Self::Field`] fails to deserialize
    fn to_form_state(&self) -> FormState<Self::Field> {
        FormState::from_form(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct TestForm {
        foo: String,
        bar: String,
    }

    #[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum TestFormField {
        Foo,
        Bar,
    }

    impl FormField for TestFormField {
        fn keep(&self) -> bool {
            match self {
                Self::Foo => true,
                Self::Bar => false,
            }
        }
    }

    impl ToFormState for TestForm {
        type Field = TestFormField;
    }

    #[test]
    fn form_state_serialization() {
        let form = TestForm {
            foo: "john".to_owned(),
            bar: "hunter2".to_owned(),
        };

        let state = form.to_form_state();
        let state = serde_json::to_value(state).unwrap();
        assert_eq!(
            state,
            serde_json::json!({
                "errors": [],
                "fields": {
                    "foo": {
                        "errors": [],
                        "value": "john",
                    },
                    "bar": {
                        "errors": [],
                        "value": null
                    },
                }
            })
        );

        let form = TestForm {
            foo: String::new(),
            bar: String::new(),
        };
        let state = form
            .to_form_state()
            .with_error_on_field(TestFormField::Foo, FieldError::Required)
            .with_error_on_field(TestFormField::Bar, FieldError::Required)
            .with_error_on_form(FormError::InvalidCredentials);

        let state = serde_json::to_value(state).unwrap();
        assert_eq!(
            state,
            serde_json::json!({
                "errors": [{"kind": "invalid_credentials"}],
                "fields": {
                    "foo": {
                        "errors": [{"kind": "required"}],
                        "value": "",
                    },
                    "bar": {
                        "errors": [{"kind": "required"}],
                        "value": null
                    },
                }
            })
        );
    }
}
