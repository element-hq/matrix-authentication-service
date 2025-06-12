// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::HashSet;

use mas_iana::jose::{JsonWebKeyType, JsonWebKeyUse, JsonWebSignatureAlg};

use crate::jwt::JsonWebSignatureHeader;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Constraint<'a> {
    Alg {
        constraint_alg: &'a JsonWebSignatureAlg,
    },

    Algs {
        constraint_algs: &'a [JsonWebSignatureAlg],
    },

    Kid {
        constraint_kid: &'a str,
    },

    Use {
        constraint_use: &'a JsonWebKeyUse,
    },

    Kty {
        constraint_kty: &'a JsonWebKeyType,
    },
}

impl<'a> Constraint<'a> {
    #[must_use]
    pub fn alg(constraint_alg: &'a JsonWebSignatureAlg) -> Self {
        Constraint::Alg { constraint_alg }
    }

    #[must_use]
    pub fn algs(constraint_algs: &'a [JsonWebSignatureAlg]) -> Self {
        Constraint::Algs { constraint_algs }
    }

    #[must_use]
    pub fn kid(constraint_kid: &'a str) -> Self {
        Constraint::Kid { constraint_kid }
    }

    #[must_use]
    pub fn use_(constraint_use: &'a JsonWebKeyUse) -> Self {
        Constraint::Use { constraint_use }
    }

    #[must_use]
    pub fn kty(constraint_kty: &'a JsonWebKeyType) -> Self {
        Constraint::Kty { constraint_kty }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintDecision {
    Positive,
    Neutral,
    Negative,
}

pub trait Constrainable {
    fn alg(&self) -> Option<&JsonWebSignatureAlg> {
        None
    }

    /// List of available algorithms for this key
    fn algs(&self) -> &[JsonWebSignatureAlg] {
        &[]
    }

    /// Key ID (`kid`) of this key
    fn kid(&self) -> Option<&str> {
        None
    }

    /// Usage specified for this key
    fn use_(&self) -> Option<&JsonWebKeyUse> {
        None
    }

    /// Key type (`kty`) of this key
    fn kty(&self) -> JsonWebKeyType;
}

impl Constraint<'_> {
    fn decide<T: Constrainable>(&self, constrainable: &T) -> ConstraintDecision {
        match self {
            Constraint::Alg { constraint_alg } => {
                // If the constrainable has one specific alg defined, use that
                if let Some(alg) = constrainable.alg() {
                    if alg == *constraint_alg {
                        ConstraintDecision::Positive
                    } else {
                        ConstraintDecision::Negative
                    }
                // If not, check that the requested alg is valid for this
                // constrainable
                } else if constrainable.algs().contains(constraint_alg) {
                    ConstraintDecision::Neutral
                } else {
                    ConstraintDecision::Negative
                }
            }
            Constraint::Algs { constraint_algs } => {
                if let Some(alg) = constrainable.alg() {
                    if constraint_algs.contains(alg) {
                        ConstraintDecision::Positive
                    } else {
                        ConstraintDecision::Negative
                    }
                } else if constrainable
                    .algs()
                    .iter()
                    .any(|alg| constraint_algs.contains(alg))
                {
                    ConstraintDecision::Neutral
                } else {
                    ConstraintDecision::Negative
                }
            }
            Constraint::Kid { constraint_kid } => {
                if let Some(kid) = constrainable.kid() {
                    if kid == *constraint_kid {
                        ConstraintDecision::Positive
                    } else {
                        ConstraintDecision::Negative
                    }
                } else {
                    ConstraintDecision::Neutral
                }
            }
            Constraint::Use { constraint_use } => {
                if let Some(use_) = constrainable.use_() {
                    if use_ == *constraint_use {
                        ConstraintDecision::Positive
                    } else {
                        ConstraintDecision::Negative
                    }
                } else {
                    ConstraintDecision::Neutral
                }
            }
            Constraint::Kty { constraint_kty } => {
                if **constraint_kty == constrainable.kty() {
                    ConstraintDecision::Positive
                } else {
                    ConstraintDecision::Negative
                }
            }
        }
    }
}

#[derive(Default)]
pub struct ConstraintSet<'a> {
    constraints: HashSet<Constraint<'a>>,
}

impl<'a> FromIterator<Constraint<'a>> for ConstraintSet<'a> {
    fn from_iter<T: IntoIterator<Item = Constraint<'a>>>(iter: T) -> Self {
        Self {
            constraints: HashSet::from_iter(iter),
        }
    }
}

#[allow(dead_code)]
impl<'a> ConstraintSet<'a> {
    pub fn new(constraints: impl IntoIterator<Item = Constraint<'a>>) -> Self {
        constraints.into_iter().collect()
    }

    pub fn filter<'b, T: Constrainable, I: IntoIterator<Item = &'b T>>(
        &self,
        constrainables: I,
    ) -> Vec<&'b T> {
        let mut selected = Vec::new();

        'outer: for constrainable in constrainables {
            let mut score = 0;

            for constraint in &self.constraints {
                match constraint.decide(constrainable) {
                    ConstraintDecision::Positive => score += 1,
                    ConstraintDecision::Neutral => {}
                    // If any constraint was negative, don't add it to the candidates
                    ConstraintDecision::Negative => continue 'outer,
                }
            }

            selected.push((score, constrainable));
        }

        selected.sort_by_key(|(score, _)| *score);

        selected
            .into_iter()
            .map(|(_score, constrainable)| constrainable)
            .collect()
    }

    #[must_use]
    pub fn alg(mut self, constraint_alg: &'a JsonWebSignatureAlg) -> Self {
        self.constraints.insert(Constraint::alg(constraint_alg));
        self
    }

    #[must_use]
    pub fn algs(mut self, constraint_algs: &'a [JsonWebSignatureAlg]) -> Self {
        self.constraints.insert(Constraint::algs(constraint_algs));
        self
    }

    #[must_use]
    pub fn kid(mut self, constraint_kid: &'a str) -> Self {
        self.constraints.insert(Constraint::kid(constraint_kid));
        self
    }

    #[must_use]
    pub fn use_(mut self, constraint_use: &'a JsonWebKeyUse) -> Self {
        self.constraints.insert(Constraint::use_(constraint_use));
        self
    }

    #[must_use]
    pub fn kty(mut self, constraint_kty: &'a JsonWebKeyType) -> Self {
        self.constraints.insert(Constraint::kty(constraint_kty));
        self
    }
}

impl<'a> From<&'a JsonWebSignatureHeader> for ConstraintSet<'a> {
    fn from(header: &'a JsonWebSignatureHeader) -> Self {
        let mut constraints = Self::default().alg(header.alg());

        if let Some(kid) = header.kid() {
            constraints = constraints.kid(kid);
        }

        constraints
    }
}
