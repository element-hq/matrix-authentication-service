// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(clippy::result_large_err)]

use std::str::FromStr;

use pest::{Parser, Span, error::ErrorVariant, iterators::Pair};

use super::message::{
    ArgumentReference, Message, PaddingSpecifier, Part, Placeholder, TypeSpecifier,
};

#[derive(pest_derive::Parser)]
#[grammar = "sprintf/grammar.pest"]
struct SprintfParser;

pub type Error = pest::error::Error<Rule>;
type Result<T, E = Error> = std::result::Result<T, E>;

fn unexpected_rule_error(pair: &Pair<Rule>) -> Error {
    Error::new_from_span(
        ErrorVariant::CustomError {
            message: format!("Unexpected rule: {:?}", pair.as_rule()),
        },
        pair.as_span(),
    )
}

fn ensure_end_of_pairs(pairs: &mut pest::iterators::Pairs<Rule>, span: Span<'_>) -> Result<()> {
    if pairs.next().is_none() {
        Ok(())
    } else {
        Err(Error::new_from_span(
            ErrorVariant::CustomError {
                message: String::from("Expected end of pairs"),
            },
            span,
        ))
    }
}

fn next_pair<'i>(
    pairs: &mut pest::iterators::Pairs<'i, Rule>,
    span: Span<'i>,
) -> Result<Pair<'i, Rule>> {
    pairs.next().ok_or_else(|| {
        Error::new_from_span(
            ErrorVariant::CustomError {
                message: String::from("Expected pair"),
            },
            span,
        )
    })
}

fn ensure_rule_type(pair: &Pair<Rule>, rule: Rule) -> Result<()> {
    if pair.as_rule() == rule {
        Ok(())
    } else {
        Err(unexpected_rule_error(pair))
    }
}

fn interpret_ident(pair: &Pair<Rule>) -> Result<String> {
    ensure_rule_type(pair, Rule::ident)?;
    Ok(pair.as_str().to_owned())
}

fn interpret_number(pair: &Pair<Rule>) -> Result<usize> {
    ensure_rule_type(pair, Rule::number)?;
    pair.as_str().parse().map_err(|e| {
        Error::new_from_span(
            ErrorVariant::CustomError {
                message: format!("Failed to parse number: {e}"),
            },
            pair.as_span(),
        )
    })
}

fn interpret_arg_named(pair: Pair<Rule>) -> Result<ArgumentReference> {
    ensure_rule_type(&pair, Rule::arg_named)?;
    let span = pair.as_span();
    let mut pairs = pair.into_inner();

    let ident = next_pair(&mut pairs, span)?;
    let ident = interpret_ident(&ident)?;

    ensure_end_of_pairs(&mut pairs, span)?;
    Ok(ArgumentReference::Named(ident))
}

fn interpret_arg_indexed(pair: Pair<Rule>) -> Result<ArgumentReference> {
    ensure_rule_type(&pair, Rule::arg_indexed)?;
    let span = pair.as_span();
    let mut pairs = pair.into_inner();

    let number = next_pair(&mut pairs, span)?;
    let number = interpret_number(&number)?;

    ensure_end_of_pairs(&mut pairs, span)?;
    Ok(ArgumentReference::Indexed(number))
}

fn interpret_padding_specifier(pair: &Pair<Rule>) -> Result<PaddingSpecifier> {
    ensure_rule_type(pair, Rule::padding_specifier)?;
    let specifier: Vec<char> = pair.as_str().chars().collect();

    let specifier = match specifier[..] {
        ['0'] => PaddingSpecifier::Zero,
        ['\'', c] => PaddingSpecifier::Char(c),
        ref specifier => {
            return Err(Error::new_from_span(
                ErrorVariant::CustomError {
                    message: format!("Unexpected padding specifier: {specifier:?}"),
                },
                pair.as_span(),
            ));
        }
    };

    Ok(specifier)
}

fn interpret_width(pair: Pair<Rule>) -> Result<usize> {
    ensure_rule_type(&pair, Rule::width)?;
    let span = pair.as_span();
    let mut pairs = pair.into_inner();

    let number = next_pair(&mut pairs, span)?;
    let number = interpret_number(&number)?;

    ensure_end_of_pairs(&mut pairs, span)?;
    Ok(number)
}

fn interpret_precision(pair: Pair<Rule>) -> Result<usize> {
    ensure_rule_type(&pair, Rule::precision)?;
    let span = pair.as_span();
    let mut pairs = pair.into_inner();

    let number = next_pair(&mut pairs, span)?;
    let number = interpret_number(&number)?;

    ensure_end_of_pairs(&mut pairs, span)?;
    Ok(number)
}

fn interpret_type_specifier(pair: &Pair<Rule>) -> Result<TypeSpecifier> {
    ensure_rule_type(pair, Rule::type_specifier)?;
    let specifier: Vec<char> = pair.as_str().chars().collect();

    let type_specifier = match specifier[..] {
        ['b'] => TypeSpecifier::BinaryNumber,
        ['c'] => TypeSpecifier::CharacterAsciiValue,
        ['d'] => TypeSpecifier::DecimalNumber,
        ['i'] => TypeSpecifier::IntegerNumber,
        ['e'] => TypeSpecifier::ScientificNotation,
        ['u'] => TypeSpecifier::UnsignedDecimalNumber,
        ['f'] => TypeSpecifier::FloatingPointNumber,
        ['g'] => TypeSpecifier::FloatingPointNumberWithSignificantDigits,
        ['o'] => TypeSpecifier::OctalNumber,
        ['s'] => TypeSpecifier::String,
        ['t'] => TypeSpecifier::TrueOrFalse,
        ['T'] => TypeSpecifier::TypeOfArgument,
        ['v'] => TypeSpecifier::PrimitiveValue,
        ['x'] => TypeSpecifier::HexadecimalNumberLowercase,
        ['X'] => TypeSpecifier::HexadecimalNumberUppercase,
        ['j'] => TypeSpecifier::Json,
        _ => {
            return Err(Error::new_from_span(
                ErrorVariant::CustomError {
                    message: String::from("Unexpected type specifier"),
                },
                pair.as_span(),
            ));
        }
    };

    Ok(type_specifier)
}

fn interpret_placeholder(pair: Pair<Rule>) -> Result<Placeholder> {
    ensure_rule_type(&pair, Rule::placeholder)?;
    let span = pair.as_span();
    let mut pairs = pair.into_inner();
    let mut current_pair = next_pair(&mut pairs, span)?;

    let argument = if current_pair.as_rule() == Rule::arg_named {
        let argument = interpret_arg_named(current_pair)?;
        current_pair = next_pair(&mut pairs, span)?;
        Some(argument)
    } else if current_pair.as_rule() == Rule::arg_indexed {
        let argument = interpret_arg_indexed(current_pair)?;
        current_pair = next_pair(&mut pairs, span)?;
        Some(argument)
    } else {
        None
    };

    let plus_sign = if current_pair.as_rule() == Rule::plus_sign {
        current_pair = next_pair(&mut pairs, span)?;
        true
    } else {
        false
    };

    let padding_specifier = if current_pair.as_rule() == Rule::padding_specifier {
        let padding_specifier = interpret_padding_specifier(&current_pair)?;
        current_pair = next_pair(&mut pairs, span)?;
        Some(padding_specifier)
    } else {
        None
    };

    let left_align = if current_pair.as_rule() == Rule::left_align {
        current_pair = next_pair(&mut pairs, span)?;
        true
    } else {
        false
    };

    let width = if current_pair.as_rule() == Rule::width {
        let width = interpret_width(current_pair)?;
        current_pair = next_pair(&mut pairs, span)?;
        Some(width)
    } else {
        None
    };

    let precision = if current_pair.as_rule() == Rule::precision {
        let precision = interpret_precision(current_pair)?;
        current_pair = next_pair(&mut pairs, span)?;
        Some(precision)
    } else {
        None
    };

    let type_specifier = interpret_type_specifier(&current_pair)?;

    ensure_end_of_pairs(&mut pairs, span)?;

    Ok(Placeholder {
        type_specifier,
        requested_argument: argument,
        plus_sign,
        padding_specifier,
        left_align,
        width,
        precision,
    })
}

impl FromStr for Message {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        SprintfParser::parse(Rule::message, input)?
            // Filter out the "end of input" rule
            .filter(|pair| pair.as_rule() != Rule::EOI)
            .map(|pair| match pair.as_rule() {
                Rule::text => Ok(pair.as_str().to_owned().into()),
                Rule::percent => Ok(Part::Percent),
                Rule::placeholder => Ok(interpret_placeholder(pair)?.into()),
                _ => Err(unexpected_rule_error(&pair)),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser() {
        // Cases extracted from sprintf-js tests
        let cases = [
            "%%",
            "%'_-5s",
            "%'_5s",
            "%+'_10d",
            "%+.1f",
            "%+010d",
            "%+d",
            "%+f",
            "%+i",
            "%-5s",
            "%.1f",
            "%.1g",
            "%.1t",
            "%.3g",
            "%.6g",
            "%0-5s",
            "%02u",
            "%05d",
            "%05i",
            "%05s",
            "%2$s %3$s a %1$s",
            "%2j",
            "%5.1s",
            "%5.5s",
            "%5s",
            "%8.3f",
            "%T",
            "%X",
            "%b",
            "%c",
            "%d",
            "%e",
            "%f",
            "%f %f",
            "%f %s",
            "%g",
            "%i",
            "%j",
            "%o",
            "%s",
            "%t",
            "%u",
            "%v",
            "%x",
            "Hello %(who)s!",
        ];

        for case in cases {
            let result: Result<Message> = case.parse();
            assert!(result.is_ok(), "Failed to parse: {case}");
            let message = result.unwrap();
            assert_eq!(message.to_string(), *case);
        }
    }
}
