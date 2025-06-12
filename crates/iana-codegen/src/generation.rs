// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use crate::traits::{EnumMember, Section};

fn raw_string(string: &str) -> String {
    if string.contains('"') {
        format!(r##"r#"{string}"#"##)
    } else {
        format!(r#"r"{string}""#)
    }
}

pub fn struct_def(
    f: &mut std::fmt::Formatter<'_>,
    section: &Section,
    list: &[EnumMember],
    is_exhaustive: bool,
) -> std::fmt::Result {
    write!(
        f,
        r"/// {}
///
/// Source: <{}>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]",
        section.doc,
        section.url.unwrap(),
    )?;

    if !is_exhaustive {
        write!(
            f,
            r"
#[non_exhaustive]"
        )?;
    }

    write!(
        f,
        r"
pub enum {} {{",
        section.key,
    )?;
    for member in list {
        writeln!(f)?;
        if let Some(description) = &member.description {
            writeln!(f, "    /// {description}")?;
        } else {
            writeln!(f, "    /// `{}`", member.value)?;
        }
        writeln!(f, "    {},", member.enum_name)?;
    }

    if !is_exhaustive {
        // Add a variant for custom enums
        writeln!(f)?;
        writeln!(f, "    /// An unknown value.")?;
        writeln!(f, "    Unknown(String),")?;
    }

    writeln!(f, "}}")
}

pub fn display_impl(
    f: &mut std::fmt::Formatter<'_>,
    section: &Section,
    list: &[EnumMember],
    is_exhaustive: bool,
) -> std::fmt::Result {
    write!(
        f,
        r"impl core::fmt::Display for {} {{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {{
        match self {{",
        section.key,
    )?;

    for member in list {
        write!(
            f,
            r#"
            Self::{} => write!(f, "{}"),"#,
            member.enum_name, member.value
        )?;
    }

    if !is_exhaustive {
        write!(
            f,
            r#"
            Self::Unknown(value) => write!(f, "{{value}}"),"#
        )?;
    }

    writeln!(
        f,
        r"
        }}
    }}
}}",
    )
}

pub fn from_str_impl(
    f: &mut std::fmt::Formatter<'_>,
    section: &Section,
    list: &[EnumMember],
    is_exhaustive: bool,
) -> std::fmt::Result {
    let err_ty = if is_exhaustive {
        "crate::ParseError"
    } else {
        "core::convert::Infallible"
    };
    write!(
        f,
        r"impl core::str::FromStr for {} {{
    type Err = {err_ty};

    fn from_str(s: &str) -> Result<Self, Self::Err> {{
        match s {{",
        section.key,
    )?;

    for member in list {
        write!(
            f,
            r#"
            "{}" => Ok(Self::{}),"#,
            member.value, member.enum_name
        )?;
    }

    if is_exhaustive {
        write!(
            f,
            r"
            _ => Err(crate::ParseError::new()),"
        )?;
    } else {
        write!(
            f,
            r"
            value => Ok(Self::Unknown(value.to_owned())),",
        )?;
    }

    writeln!(
        f,
        r"
        }}
    }}
}}",
    )
}

pub fn json_schema_impl(
    f: &mut std::fmt::Formatter<'_>,
    section: &Section,
    list: &[EnumMember],
) -> std::fmt::Result {
    write!(
        f,
        r#"impl schemars::JsonSchema for {} {{
    fn schema_name() -> std::borrow::Cow<'static, str> {{
        std::borrow::Cow::Borrowed("{}")
    }}

    #[allow(clippy::too_many_lines)]
    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {{
        let enums = vec!["#,
        section.key, section.key,
    )?;

    for member in list {
        write!(
            f,
            r"
            // ---
            schemars::json_schema!({{",
        )?;

        if let Some(description) = &member.description {
            write!(
                f,
                r#"
                "description": {},"#,
                raw_string(description),
            )?;
        }

        write!(
            f,
            r#"
                "const": "{}",
            }}),"#,
            member.value
        )?;
    }

    writeln!(
        f,
        r#"
        ];

        let description = {};
        schemars::json_schema!({{
            "description": description,
            "anyOf": enums,
        }})
    }}
}}"#,
        raw_string(section.doc),
    )
}

pub fn serde_impl(f: &mut std::fmt::Formatter<'_>, section: &Section) -> std::fmt::Result {
    writeln!(
        f,
        r"impl<'de> serde::Deserialize<'de> for {} {{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {{
        let s = String::deserialize(deserializer)?;
        core::str::FromStr::from_str(&s).map_err(serde::de::Error::custom)
    }}
}}

impl serde::Serialize for {} {{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {{
        serializer.serialize_str(&self.to_string())
    }}
}}",
        section.key, section.key,
    )
}
