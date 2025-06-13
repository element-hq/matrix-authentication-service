// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashMap;

use serde_json::Value;

/// A list of arguments that can be accessed by index or name.
#[derive(Debug, Clone, Default)]
pub struct List {
    arguments: Vec<Value>,
    name_index: HashMap<String, usize>,
}

impl List {
    /// Get an argument by its index.
    #[must_use]
    pub fn get_by_index(&self, index: usize) -> Option<&Value> {
        self.arguments.get(index)
    }

    /// Get an argument by its name.
    #[must_use]
    pub fn get_by_name(&self, name: &str) -> Option<&Value> {
        self.name_index
            .get(name)
            .and_then(|index| self.get_by_index(*index))
    }
}

impl<A: Into<Argument>> FromIterator<A> for List {
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let mut arguments = Vec::new();
        let mut name_index = HashMap::new();

        for (index, argument) in iter.into_iter().enumerate() {
            let argument = argument.into();
            if let Some(name) = argument.name {
                name_index.insert(name.clone(), index);
            }

            arguments.push(argument.value);
        }

        Self {
            arguments,
            name_index,
        }
    }
}

/// A single argument value.
pub struct Argument {
    name: Option<String>,
    value: Value,
}

impl From<Value> for Argument {
    fn from(value: Value) -> Self {
        Self { name: None, value }
    }
}

impl From<(&str, Value)> for Argument {
    fn from((name, value): (&str, Value)) -> Self {
        Self {
            name: Some(name.to_owned()),
            value,
        }
    }
}

impl From<(String, Value)> for Argument {
    fn from((name, value): (String, Value)) -> Self {
        Self {
            name: Some(name),
            value,
        }
    }
}

impl Argument {
    /// Create a new argument with the given name and value.
    #[must_use]
    pub fn named(name: String, value: Value) -> Self {
        Self {
            name: Some(name),
            value,
        }
    }

    /// Set the name of the argument.
    #[must_use]
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_argument_list() {
        let list = List::from_iter([
            ("hello", json!("world")),
            ("alice", json!(null)),
            ("bob", json!(42)),
        ]);

        assert_eq!(list.get_by_index(0), Some(&json!("world")));
        assert_eq!(list.get_by_index(1), Some(&json!(null)));
        assert_eq!(list.get_by_index(2), Some(&json!(42)));
        assert_eq!(list.get_by_index(3), None);

        assert_eq!(list.get_by_name("hello"), Some(&json!("world")));
        assert_eq!(list.get_by_name("alice"), Some(&json!(null)));
        assert_eq!(list.get_by_name("bob"), Some(&json!(42)));
        assert_eq!(list.get_by_name("charlie"), None);

        let list = List::from_iter([
            Argument::from(json!("hello")),
            Argument::named("alice".to_owned(), json!(null)),
            Argument::named("bob".to_owned(), json!(42)),
        ]);

        assert_eq!(list.get_by_index(0), Some(&json!("hello")));
        assert_eq!(list.get_by_index(1), Some(&json!(null)));
        assert_eq!(list.get_by_index(2), Some(&json!(42)));
        assert_eq!(list.get_by_index(3), None);

        assert_eq!(list.get_by_name("hello"), None);
        assert_eq!(list.get_by_name("alice"), Some(&json!(null)));
        assert_eq!(list.get_by_name("bob"), Some(&json!(42)));
        assert_eq!(list.get_by_name("charlie"), None);
    }
}
