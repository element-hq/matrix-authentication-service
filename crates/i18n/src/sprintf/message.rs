// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use serde::{Deserialize, Serialize};

/// Specifies how to format an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeSpecifier {
    /// `b`
    BinaryNumber,

    /// `c`
    CharacterAsciiValue,

    /// `i`
    DecimalNumber,

    /// `i`
    IntegerNumber,

    /// `e`
    ScientificNotation,

    /// `u`
    UnsignedDecimalNumber,

    /// `f`
    FloatingPointNumber,

    /// `g`
    FloatingPointNumberWithSignificantDigits,

    /// `o`
    OctalNumber,

    /// `s`
    String,

    /// `t`
    TrueOrFalse,

    /// `T`
    TypeOfArgument,

    /// `v`
    PrimitiveValue,

    /// `x`
    HexadecimalNumberLowercase,

    /// `X`
    HexadecimalNumberUppercase,

    /// `j`
    Json,
}

impl TypeSpecifier {
    /// Returns true if the type specifier is a numeric type, which should be
    /// specially formatted with the zero
    const fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::BinaryNumber
                | Self::DecimalNumber
                | Self::IntegerNumber
                | Self::ScientificNotation
                | Self::UnsignedDecimalNumber
                | Self::FloatingPointNumber
                | Self::FloatingPointNumberWithSignificantDigits
                | Self::OctalNumber
                | Self::HexadecimalNumberLowercase
                | Self::HexadecimalNumberUppercase
        )
    }
}

impl std::fmt::Display for TypeSpecifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let specifier = match self {
            Self::BinaryNumber => 'b',
            Self::CharacterAsciiValue => 'c',
            Self::DecimalNumber => 'd',
            Self::IntegerNumber => 'i',
            Self::ScientificNotation => 'e',
            Self::UnsignedDecimalNumber => 'u',
            Self::FloatingPointNumber => 'f',
            Self::FloatingPointNumberWithSignificantDigits => 'g',
            Self::OctalNumber => 'o',
            Self::String => 's',
            Self::TrueOrFalse => 't',
            Self::TypeOfArgument => 'T',
            Self::PrimitiveValue => 'v',
            Self::HexadecimalNumberLowercase => 'x',
            Self::HexadecimalNumberUppercase => 'X',
            Self::Json => 'j',
        };
        write!(f, "{specifier}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgumentReference {
    Indexed(usize),
    Named(String),
}

impl std::fmt::Display for ArgumentReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgumentReference::Indexed(index) => write!(f, "{index}$"),
            ArgumentReference::Named(name) => write!(f, "({name})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingSpecifier {
    Zero,
    Char(char),
}

impl std::fmt::Display for PaddingSpecifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PaddingSpecifier::Zero => write!(f, "0"),
            PaddingSpecifier::Char(c) => write!(f, "'{c}"),
        }
    }
}

impl PaddingSpecifier {
    pub fn char(self) -> char {
        match self {
            PaddingSpecifier::Zero => '0',
            PaddingSpecifier::Char(c) => c,
        }
    }

    pub const fn is_zero(self) -> bool {
        match self {
            PaddingSpecifier::Zero => true,
            PaddingSpecifier::Char(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    pub type_specifier: TypeSpecifier,
    pub requested_argument: Option<ArgumentReference>,
    pub plus_sign: bool,
    pub padding_specifier: Option<PaddingSpecifier>,
    pub left_align: bool,
    pub width: Option<usize>,
    pub precision: Option<usize>,
}

impl Placeholder {
    pub fn padding_specifier_is_zero(&self) -> bool {
        self.padding_specifier
            .is_some_and(PaddingSpecifier::is_zero)
    }

    /// Whether it should be formatted as a number for the width argument
    pub fn numeric_width(&self) -> Option<usize> {
        self.width
            .filter(|_| self.padding_specifier_is_zero() && self.type_specifier.is_numeric())
    }
}

impl std::fmt::Display for Placeholder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "%")?;
        if let Some(argument) = &self.requested_argument {
            write!(f, "{argument}")?;
        }

        if self.plus_sign {
            write!(f, "+")?;
        }

        if let Some(padding_specifier) = &self.padding_specifier {
            write!(f, "{padding_specifier}")?;
        }

        if self.left_align {
            write!(f, "-")?;
        }

        if let Some(width) = self.width {
            write!(f, "{width}")?;
        }

        if let Some(precision) = self.precision {
            write!(f, ".{precision}")?;
        }

        write!(f, "{}", self.type_specifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    parts: Vec<Part>,
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for part in &self.parts {
            write!(f, "{part}")?;
        }
        Ok(())
    }
}

impl FromIterator<Part> for Message {
    fn from_iter<T: IntoIterator<Item = Part>>(iter: T) -> Self {
        Self {
            parts: iter.into_iter().collect(),
        }
    }
}

impl Message {
    pub(crate) fn parts(&self) -> std::slice::Iter<'_, Part> {
        self.parts.iter()
    }

    /// Create a message from a literal string, without any placeholders.
    #[must_use]
    pub fn from_literal(literal: String) -> Message {
        Message {
            parts: vec![Part::Text(literal)],
        }
    }
}

impl Serialize for Message {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let string = self.to_string();
        serializer.serialize_str(&string)
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = String::deserialize(deserializer)?;
        string.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Part {
    Percent,
    Text(String),
    Placeholder(Placeholder),
}

impl From<Placeholder> for Part {
    fn from(placeholder: Placeholder) -> Self {
        Self::Placeholder(placeholder)
    }
}

impl From<String> for Part {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl std::fmt::Display for Part {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Part::Percent => write!(f, "%%"),
            Part::Text(text) => write!(f, "{text}"),
            Part::Placeholder(placeholder) => write!(f, "{placeholder}"),
        }
    }
}
