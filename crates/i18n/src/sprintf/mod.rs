// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(unused_macros)]

mod argument;
mod formatter;
mod message;
mod parser;

pub use self::{
    argument::{Argument, List as ArgumentList},
    formatter::{FormatError, FormattedMessage, FormattedMessagePart},
    message::Message,
};

macro_rules! arg_list_inner {
    ($var:ident |) => { };
    ($var:ident | $name:ident = $($arg:expr)*, $($rest:tt)*) => {{
        $var.push($crate::sprintf::Argument::from((stringify!($name), ::serde_json::json!($($arg)*))));
        $crate::sprintf::arg_list_inner!($var | $($rest)* );
    }};
    ($var:ident | $name:ident = $($arg:expr)*) => {{
        $var.push($crate::sprintf::Argument::from((stringify!($name), ::serde_json::json!($($arg)*))));
    }};
    ($var:ident | $($arg:expr)*, $($rest:tt)*) => {{
        $var.push($crate::sprintf::Argument::from(::serde_json::json!($($arg)*)));
        $crate::sprintf::arg_list_inner!($var | $($rest)* );
    }};
    ($var:ident | $($arg:expr)*) => {{
        $var.push($crate::sprintf::Argument::from(::serde_json::json!($($arg)*)));
    }};
}

macro_rules! arg_list {
    ($($args:tt)*) => {{
        let mut __args = Vec::<$crate::sprintf::Argument>::new();
        $crate::sprintf::arg_list_inner!(__args | $($args)* );
        $crate::sprintf::ArgumentList::from_iter(__args)
    }}
}

macro_rules! sprintf {
    ($message:literal) => {{
        <$crate::sprintf::Message as ::std::str::FromStr>::from_str($message)
            .map_err($crate::sprintf::Error::from)
            .and_then(|message| {
                let __args = $crate::sprintf::ArgumentList::default();
                message.format(&__args).map_err($crate::sprintf::Error::from)
            })
    }};

    ($message:literal, $($args:tt)*) => {{
        <$crate::sprintf::Message as ::std::str::FromStr>::from_str($message)
            .map_err($crate::sprintf::Error::from)
            .and_then(|message| {
                let __args = $crate::sprintf::arg_list!($($args)*);
                message.format(&__args).map_err($crate::sprintf::Error::from)
            })
    }};
}

#[allow(unused_imports)]
pub(crate) use arg_list;
#[allow(unused_imports)]
pub(crate) use arg_list_inner;
#[allow(unused_imports)]
pub(crate) use sprintf;

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
enum Error {
    Format(#[from] self::formatter::FormatError),
    Parse(Box<self::parser::Error>),
}

impl From<self::parser::Error> for Error {
    fn from(err: self::parser::Error) -> Self {
        Self::Parse(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use std::f64::consts::PI;

    #[test]
    fn test_sprintf() {
        let res = sprintf!("Hello, %(name)s!", name = "world").unwrap();
        assert_eq!(res, "Hello, world!");
        assert_eq!("%", sprintf!("%%").unwrap());
        assert_eq!("10", sprintf!("%b", 2).unwrap());
        assert_eq!("A", sprintf!("%c", 65).unwrap());
        assert_eq!("2", sprintf!("%d", 2).unwrap());
        assert_eq!("2", sprintf!("%i", 2).unwrap());
        //assert_eq!("2", sprintf!("%d", "2").unwrap()); -- We don't convert on the fly
        //assert_eq!("2", sprintf!("%i", "2").unwrap()); -- We don't convert on the fly
        assert_eq!(
            r#"{"foo":"bar"}"#,
            sprintf!("%j", serde_json::json!({"foo": "bar"})).unwrap()
        );
        assert_eq!(r#"["foo","bar"]"#, sprintf!("%j", ["foo", "bar"]).unwrap());
        assert_eq!("2e0", sprintf!("%e", 2).unwrap()); // sprintf-js returns 2e+0
        assert_eq!("2", sprintf!("%u", 2).unwrap());
        assert_eq!("4294967294", sprintf!("%u", -2).unwrap());
        assert_eq!("2.2", sprintf!("%f", 2.2).unwrap());
        assert_eq!("3.141592653589793", sprintf!("%g", PI).unwrap());
        assert_eq!("10", sprintf!("%o", 8).unwrap());
        assert_eq!("37777777770", sprintf!("%o", -8).unwrap());
        assert_eq!("%s", sprintf!("%s", "%s").unwrap());
        assert_eq!("ff", sprintf!("%x", 255).unwrap());
        assert_eq!("ffffff01", sprintf!("%x", -255).unwrap());
        assert_eq!("FF", sprintf!("%X", 255).unwrap());
        assert_eq!("FFFFFF01", sprintf!("%X", -255).unwrap());
        assert_eq!(
            "Polly wants a cracker",
            sprintf!("%2$s %3$s a %1$s", "cracker", "Polly", "wants").unwrap()
        );
        assert_eq!(
            "Hello world!",
            sprintf!("Hello %(who)s!", who = "world").unwrap()
        );

        assert_eq!("true", sprintf!("%t", true).unwrap());
        assert_eq!("t", sprintf!("%.1t", true).unwrap());
        // We don't implement truthiness
        //assert_eq!("true", sprintf!("%t", "true").unwrap());
        //assert_eq!("true", sprintf!("%t", 1).unwrap());
        assert_eq!("false", sprintf!("%t", false).unwrap());
        assert_eq!("f", sprintf!("%.1t", false).unwrap());
        //assert_eq!("false", sprintf!("%t", "").unwrap());
        //assert_eq!("false", sprintf!("%t", 0).unwrap());

        assert_eq!("null", sprintf!("%T", serde_json::json!(null)).unwrap());
        assert_eq!("boolean", sprintf!("%T", true).unwrap());
        assert_eq!("number", sprintf!("%T", 42).unwrap());
        assert_eq!("string", sprintf!("%T", "This is a string").unwrap());
        assert_eq!("array", sprintf!("%T", [1, 2, 3]).unwrap());
        assert_eq!(
            "object",
            sprintf!("%T", serde_json::json!({"foo": "bar"})).unwrap()
        );
    }

    #[test]
    fn test_complex() {
        // sign
        assert_eq!("2", sprintf!("%d", 2).unwrap());
        assert_eq!("-2", sprintf!("%d", -2).unwrap());
        assert_eq!("+2", sprintf!("%+d", 2).unwrap());
        assert_eq!("-2", sprintf!("%+d", -2).unwrap());
        assert_eq!("2", sprintf!("%i", 2).unwrap());
        assert_eq!("-2", sprintf!("%i", -2).unwrap());
        assert_eq!("+2", sprintf!("%+i", 2).unwrap());
        assert_eq!("-2", sprintf!("%+i", -2).unwrap());
        assert_eq!("2.2", sprintf!("%f", 2.2).unwrap());
        assert_eq!("-2.2", sprintf!("%f", -2.2).unwrap());
        assert_eq!("+2.2", sprintf!("%+f", 2.2).unwrap());
        assert_eq!("-2.2", sprintf!("%+f", -2.2).unwrap());
        assert_eq!("-2.3", sprintf!("%+.1f", -2.34).unwrap());
        assert_eq!("-0.0", sprintf!("%+.1f", -0.01).unwrap());

        assert_eq!("3.14159", sprintf!("%.6g", PI).unwrap());
        assert_eq!("3.14", sprintf!("%.3g", PI).unwrap());
        assert_eq!("3", sprintf!("%.1g", PI).unwrap());
        assert_eq!("3e5", sprintf!("%.1g", 300_000.0).unwrap());
        assert_eq!("300", sprintf!("%.3g", 300).unwrap());

        assert_eq!("-000000123", sprintf!("%+010d", -123).unwrap());
        assert_eq!("______-123", sprintf!("%+'_10d", -123).unwrap());
        assert_eq!("-234.34 123.2", sprintf!("%f %f", -234.34, 123.2).unwrap());

        // padding
        assert_eq!("-0002", sprintf!("%05d", -2).unwrap());
        assert_eq!("-0002", sprintf!("%05i", -2).unwrap());
        assert_eq!("    <", sprintf!("%5s", "<").unwrap());
        assert_eq!("0000<", sprintf!("%05s", "<").unwrap());
        assert_eq!("____<", sprintf!("%'_5s", "<").unwrap());
        assert_eq!(">    ", sprintf!("%-5s", ">").unwrap());
        assert_eq!(">0000", sprintf!("%0-5s", ">").unwrap());
        assert_eq!(">____", sprintf!("%'_-5s", ">").unwrap());
        assert_eq!("xxxxxx", sprintf!("%5s", "xxxxxx").unwrap());
        assert_eq!("1234", sprintf!("%02u", 1234).unwrap());
        assert_eq!(" -10.235", sprintf!("%8.3f", -10.23456).unwrap());
        assert_eq!("-12.34 xxx", sprintf!("%f %s", -12.34, "xxx").unwrap());
        assert_eq!(
            r#"{
  "foo": "bar"
}"#,
            sprintf!("%2j", serde_json::json!({"foo": "bar"})).unwrap()
        );
        assert_eq!(
            r#"[
  "foo",
  "bar"
]"#,
            sprintf!("%2j", ["foo", "bar"]).unwrap()
        );

        // precision
        assert_eq!("2.3", sprintf!("%.1f", 2.345).unwrap());
        assert_eq!("xxxxx", sprintf!("%5.5s", "xxxxxx").unwrap());
        assert_eq!("    x", sprintf!("%5.1s", "xxxxxx").unwrap());
    }
}
