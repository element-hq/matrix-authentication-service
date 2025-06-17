// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Deref,
};

use icu_plurals::PluralCategory;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{MapAccess, Visitor},
    ser::SerializeMap,
};

use crate::sprintf::Message;

fn plural_category_as_str(category: PluralCategory) -> &'static str {
    match category {
        PluralCategory::Zero => "zero",
        PluralCategory::One => "one",
        PluralCategory::Two => "two",
        PluralCategory::Few => "few",
        PluralCategory::Many => "many",
        PluralCategory::Other => "other",
    }
}

pub type TranslationTree = Tree;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Metadata {
    #[serde(skip)]
    // We don't want to deserialize it, as we're resetting it every time
    // This then generates the `context` field when serializing
    pub context_locations: BTreeSet<String>,
    pub description: Option<String>,
}

impl Serialize for Metadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let context = self
            .context_locations
            .iter()
            .map(String::as_str)
            .collect::<Vec<&str>>()
            .join(", ");

        let mut map = serializer.serialize_map(None)?;

        if !context.is_empty() {
            map.serialize_entry("context", &context)?;
        }

        if let Some(description) = &self.description {
            map.serialize_entry("description", description)?;
        }

        map.end()
    }
}

impl Metadata {
    fn add_location(&mut self, location: String) {
        self.context_locations.insert(location);
    }
}

#[derive(Debug, Clone, Default)]
pub struct Tree {
    inner: BTreeMap<String, Node>,
}

#[derive(Debug, Clone)]
pub struct Node {
    metadata: Option<Metadata>,
    value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Tree(Tree),
    Leaf(Message),
}

impl<'de> Deserialize<'de> for Tree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TreeVisitor;

        impl<'de> Visitor<'de> for TreeVisitor {
            type Value = Tree;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("map")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut tree: BTreeMap<String, Node> = BTreeMap::new();
                let mut metadata_map: BTreeMap<String, Metadata> = BTreeMap::new();

                while let Some(key) = map.next_key::<String>()? {
                    if let Some(name) = key.strip_prefix('@') {
                        let metadata = map.next_value::<Metadata>()?;
                        metadata_map.insert(name.to_owned(), metadata);
                    } else {
                        let value = map.next_value::<Value>()?;
                        tree.insert(
                            key,
                            Node {
                                metadata: None,
                                value,
                            },
                        );
                    }
                }

                for (key, meta) in metadata_map {
                    if let Some(node) = tree.get_mut(&key) {
                        node.metadata = Some(meta);
                    }
                }

                Ok(Tree { inner: tree })
            }
        }

        deserializer.deserialize_any(TreeVisitor)
    }
}

impl Serialize for Tree {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        for (key, value) in &self.inner {
            map.serialize_entry(key, &value.value)?;
            if let Some(meta) = &value.metadata {
                map.serialize_entry(&format!("@{key}"), meta)?;
            }
        }

        map.end()
    }
}

impl Tree {
    /// Get a message from the tree by key.
    ///
    /// Returns `None` if the requested key is not found.
    #[must_use]
    pub fn message(&self, key: &str) -> Option<&Message> {
        let keys = key.split('.');
        let node = self.walk_path(keys)?;
        let message = node.value.as_message()?;
        Some(message)
    }

    /// Get a pluralized message from the tree by key and plural category.
    ///
    /// If the key doesn't have plural variants, this will return the message
    /// itself. Returns the "other" category if the requested category is
    /// not found. Returns `None` if the requested key is not found.
    #[must_use]
    pub fn pluralize(&self, key: &str, category: PluralCategory) -> Option<&Message> {
        let keys = key.split('.');
        let node = self.walk_path(keys)?;

        let subtree = match &node.value {
            Value::Leaf(message) => return Some(message),
            Value::Tree(tree) => tree,
        };

        let node = if let Some(node) = subtree.inner.get(plural_category_as_str(category)) {
            node
        } else {
            // Fallback to the "other" category
            subtree.inner.get("other")?
        };

        let message = node.value.as_message()?;
        Some(message)
    }

    #[doc(hidden)]
    pub fn set_if_not_defined<K: Deref<Target = str>, I: IntoIterator<Item = K>>(
        &mut self,
        path: I,
        value: Message,
        location: Option<String>,
    ) -> bool {
        // We're temporarily moving the tree out of the struct to be able to nicely
        // iterate on it
        let mut fake_root = Node {
            metadata: None,
            value: Value::Tree(Tree {
                inner: std::mem::take(&mut self.inner),
            }),
        };

        let mut node = &mut fake_root;
        for key in path {
            match &mut node.value {
                Value::Tree(tree) => {
                    node = tree.inner.entry(key.deref().to_owned()).or_insert(Node {
                        metadata: None,
                        value: Value::Tree(Tree::default()),
                    });
                }
                Value::Leaf(_) => {
                    panic!()
                }
            }
        }

        let replaced = match &node.value {
            Value::Tree(tree) => {
                assert!(
                    tree.inner.is_empty(),
                    "Trying to overwrite a non-empty tree"
                );

                node.value = Value::Leaf(value);
                true
            }
            Value::Leaf(_) => {
                // Do not overwrite existing values
                false
            }
        };

        if let Some(location) = location {
            node.metadata
                .get_or_insert(Metadata::default())
                .add_location(location);
        }

        // Restore the original tree at the end of the function
        match fake_root {
            Node {
                value: Value::Tree(tree),
                ..
            } => self.inner = tree.inner,
            _ => panic!("Tried to replace the root node"),
        }

        replaced
    }

    fn walk_path<K: Deref<Target = str>, I: IntoIterator<Item = K>>(
        &self,
        path: I,
    ) -> Option<&Node> {
        let mut iterator = path.into_iter();
        let next = iterator.next()?;
        self.walk_path_inner(next, iterator)
    }

    fn walk_path_inner<K: Deref<Target = str>, I: Iterator<Item = K>>(
        &self,
        next_key: K,
        mut path: I,
    ) -> Option<&Node> {
        let next = self.inner.get(&*next_key)?;

        match path.next() {
            Some(next_key) => match &next.value {
                Value::Tree(tree) => tree.walk_path_inner(next_key, path),
                Value::Leaf(_) => None,
            },
            None => Some(next),
        }
    }
}

impl Value {
    fn as_message(&self) -> Option<&Message> {
        match self {
            Value::Leaf(message) => Some(message),
            Value::Tree(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sprintf::{ArgumentList, arg_list};

    #[test]
    fn test_it_works() {
        let tree = serde_json::json!({
            "hello": "world",
            "damals": {
              "about_x_hours_ago": {
                "one":   "about one hour ago",
                "other": "about %(count)s hours ago"
              }
            }
        });

        let result: Result<TranslationTree, _> = serde_json::from_value(tree);
        assert!(result.is_ok());
        let tree = result.unwrap();
        let message = tree.message("hello");
        assert!(message.is_some());
        let message = message.unwrap();
        assert_eq!(message.format(&ArgumentList::default()).unwrap(), "world");

        let message = tree.message("damals.about_x_hours_ago.one");
        assert!(message.is_some());
        let message = message.unwrap();
        assert_eq!(message.format(&arg_list!()).unwrap(), "about one hour ago");

        let message = tree.pluralize("damals.about_x_hours_ago", PluralCategory::Other);
        assert!(message.is_some());
        let message = message.unwrap();
        assert_eq!(
            message.format(&arg_list!(count = 2)).unwrap(),
            "about 2 hours ago"
        );
    }
}
