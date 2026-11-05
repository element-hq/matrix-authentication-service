// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! A minimal propagator for the Jaeger `uber-trace-id` header, the trace
//! context format Synapse uses.
//!
//! The header value is `{trace-id}:{span-id}:{parent-span-id}:{flags}`, all
//! hex-encoded, as described in
//! <https://www.jaegertracing.io/sdk-migration/#propagation-format>.
//! The parent span ID is deprecated in that format, so it is ignored on
//! extraction and sent as `0`. Baggage (`uberctx-*` headers) is not
//! propagated.

use std::borrow::Cow;

use opentelemetry::{
    Context,
    propagation::{Extractor, Injector, TextMapPropagator, text_map_propagator::FieldIter},
    trace::{SpanContext, SpanId, TraceContextExt as _, TraceFlags, TraceId, TraceState},
};

const HEADER_NAME: &str = "uber-trace-id";

/// Jaeger's debug flag has no W3C equivalent, so it is carried in a bit that
/// the W3C propagator masks out.
const TRACE_FLAG_DEBUG: TraceFlags = TraceFlags::new(0x04);

/// Propagates the trace context through the Jaeger `uber-trace-id` header
#[derive(Debug)]
pub struct JaegerPropagator {
    fields: [String; 1],
}

impl JaegerPropagator {
    pub fn new() -> Self {
        Self {
            fields: [HEADER_NAME.to_owned()],
        }
    }
}

/// Parse the value of an `uber-trace-id` header
fn parse_header(value: &str) -> Option<SpanContext> {
    // jaeger-client-python, which Synapse uses, URL-encodes the whole value
    let value = if value.contains(':') {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(value.replace("%3A", ":").replace("%3a", ":"))
    };

    let mut parts = value.split(':');
    let trace_id = parts.next()?;
    let span_id = parts.next()?;
    let _parent_span_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    // Jaeger clients drop leading zeros from the IDs, so shorter values are valid
    if trace_id.is_empty() || trace_id.len() > 32 {
        return None;
    }
    if span_id.is_empty() || span_id.len() > 16 {
        return None;
    }
    if flags.is_empty() || flags.len() > 2 {
        return None;
    }

    let trace_id = TraceId::from_hex(trace_id).ok()?;
    let span_id = SpanId::from_hex(span_id).ok()?;
    let flags = u8::from_str_radix(flags, 16).ok()?;
    // The debug flag (0x02) only has an effect on sampled traces
    let trace_flags = match flags & 0x03 {
        0x03 => TraceFlags::SAMPLED | TRACE_FLAG_DEBUG,
        0x01 => TraceFlags::SAMPLED,
        _ => TraceFlags::default(),
    };

    let span_context = SpanContext::new(trace_id, span_id, trace_flags, true, TraceState::NONE);
    span_context.is_valid().then_some(span_context)
}

impl TextMapPropagator for JaegerPropagator {
    fn inject_context(&self, cx: &Context, injector: &mut dyn Injector) {
        let span = cx.span();
        let span_context = span.span_context();
        if !span_context.is_valid() {
            return;
        }

        let flags: u8 = if !span_context.is_sampled() {
            0x00
        } else if span_context.trace_flags() & TRACE_FLAG_DEBUG == TRACE_FLAG_DEBUG {
            0x03
        } else {
            0x01
        };
        injector.set(
            HEADER_NAME,
            format!(
                "{}:{}:0:{flags:x}",
                span_context.trace_id(),
                span_context.span_id()
            ),
        );
    }

    fn extract_with_context(&self, cx: &Context, extractor: &dyn Extractor) -> Context {
        extractor
            .get(HEADER_NAME)
            .and_then(parse_header)
            .map_or_else(
                || cx.clone(),
                |span_context| cx.with_remote_span_context(span_context),
            )
    }

    fn fields(&self) -> FieldIter<'_> {
        FieldIter::new(&self.fields)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn extract(value: &str) -> Option<SpanContext> {
        let headers = HashMap::from([(HEADER_NAME.to_owned(), value.to_owned())]);
        let cx = JaegerPropagator::new().extract(&headers);
        let span = cx.span();
        let span_context = span.span_context();
        span_context.is_valid().then(|| span_context.clone())
    }

    #[test]
    fn extract_sampled() {
        let span_context =
            extract("4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:1").unwrap();
        assert_eq!(
            span_context.trace_id(),
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap()
        );
        assert_eq!(
            span_context.span_id(),
            SpanId::from_hex("00f067aa0ba902b7").unwrap()
        );
        assert!(span_context.is_sampled());
        assert!(span_context.is_remote());
    }

    #[test]
    fn extract_not_sampled() {
        let span_context =
            extract("4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:0").unwrap();
        assert!(!span_context.is_sampled());
    }

    #[test]
    fn extract_debug_flag() {
        let span_context =
            extract("4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:3").unwrap();
        assert!(span_context.is_sampled());
        assert_eq!(
            span_context.trace_flags() & TRACE_FLAG_DEBUG,
            TRACE_FLAG_DEBUG
        );
    }

    #[test]
    fn extract_debug_flag_without_sampled() {
        let span_context =
            extract("4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:2").unwrap();
        assert_eq!(span_context.trace_flags(), TraceFlags::default());
    }

    #[test]
    fn extract_synapse_header() {
        // jaeger-client-python URL-encodes the value, drops leading zeros and
        // sends a non-zero parent span ID
        let span_context =
            extract("6f3a0c1d2e4b5a69%3A1b2c3d4e5f6a7b8%3A2a3b4c5d6e7f8091%3A1").unwrap();
        assert_eq!(
            span_context.trace_id(),
            TraceId::from_hex("00000000000000006f3a0c1d2e4b5a69").unwrap()
        );
        assert_eq!(
            span_context.span_id(),
            SpanId::from_hex("01b2c3d4e5f6a7b8").unwrap()
        );
        assert!(span_context.is_sampled());
    }

    #[test]
    fn extract_short_ids() {
        let span_context = extract("a3ce929d0e0e4736:f067aa0ba902b7:0:1").unwrap();
        assert_eq!(
            span_context.trace_id(),
            TraceId::from_hex("0000000000000000a3ce929d0e0e4736").unwrap()
        );
        assert_eq!(
            span_context.span_id(),
            SpanId::from_hex("00f067aa0ba902b7").unwrap()
        );
    }

    #[test]
    fn extract_url_encoded() {
        let span_context =
            extract("4bf92f3577b34da6a3ce929d0e0e4736%3A00f067aa0ba902b7%3A0%3A1").unwrap();
        assert!(span_context.is_sampled());
    }

    #[test]
    fn extract_invalid() {
        for value in [
            "",
            "4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:1",
            "4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:1:0",
            "4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:",
            "4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:100",
            ":00f067aa0ba902b7:0:1",
            "04bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:1",
            "4bf92f3577b34da6a3ce929d0e0e4736:000f067aa0ba902b7:0:1",
            "not-hex:00f067aa0ba902b7:0:1",
            "0:00f067aa0ba902b7:0:1",
            "4bf92f3577b34da6a3ce929d0e0e4736:0:0:1",
        ] {
            assert!(extract(value).is_none(), "{value:?} should be rejected");
        }
    }

    #[test]
    fn extract_missing_header() {
        let headers: HashMap<String, String> = HashMap::new();
        let cx = JaegerPropagator::new().extract(&headers);
        assert!(!cx.span().span_context().is_valid());
    }

    #[test]
    fn inject_round_trip() {
        let span_context = SpanContext::new(
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            SpanId::from_hex("00f067aa0ba902b7").unwrap(),
            TraceFlags::SAMPLED,
            false,
            TraceState::NONE,
        );
        let cx = Context::new().with_remote_span_context(span_context.clone());

        let mut headers = HashMap::new();
        JaegerPropagator::new().inject_context(&cx, &mut headers);
        assert_eq!(
            headers.get(HEADER_NAME).map(String::as_str),
            Some("4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:1")
        );

        let extracted = extract(&headers[HEADER_NAME]).unwrap();
        assert_eq!(extracted.trace_id(), span_context.trace_id());
        assert_eq!(extracted.span_id(), span_context.span_id());
        assert!(extracted.is_sampled());
    }

    #[test]
    fn inject_debug_flag() {
        let span_context = SpanContext::new(
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
            SpanId::from_hex("00f067aa0ba902b7").unwrap(),
            TraceFlags::SAMPLED | TRACE_FLAG_DEBUG,
            false,
            TraceState::NONE,
        );
        let cx = Context::new().with_remote_span_context(span_context);

        let mut headers = HashMap::new();
        JaegerPropagator::new().inject_context(&cx, &mut headers);
        assert_eq!(
            headers.get(HEADER_NAME).map(String::as_str),
            Some("4bf92f3577b34da6a3ce929d0e0e4736:00f067aa0ba902b7:0:3")
        );
    }

    #[test]
    fn inject_without_span() {
        let mut headers = HashMap::new();
        JaegerPropagator::new().inject_context(&Context::new(), &mut headers);
        assert!(headers.is_empty());
    }
}
