// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::LazyLock;

use console::{Color, Style};
use opentelemetry::{TraceId, trace::TraceContextExt as _};
use tracing::{Level, Subscriber};
use tracing_opentelemetry::get_otel_context;
use tracing_subscriber::{
    fmt::{
        FormatEvent, FormatFields,
        format::{DefaultFields, Writer},
        time::{ChronoLocal, FormatTime},
    },
    registry::LookupSpan,
};

use crate::LogContext;

static TIMER: LazyLock<ChronoLocal> =
    LazyLock::new(|| ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.6f%:z".to_owned()));

/// An event formatter usable by the [`tracing_subscriber`] crate, which
/// includes the log context and the OTEL trace ID.
#[derive(Debug, Default)]
pub struct EventFormatter;

struct FmtLevel<'a> {
    level: &'a Level,
    ansi: bool,
}

impl<'a> FmtLevel<'a> {
    pub(crate) fn new(level: &'a Level, ansi: bool) -> Self {
        Self { level, ansi }
    }
}

const TRACE_STR: &str = "TRACE";
const DEBUG_STR: &str = "DEBUG";
const INFO_STR: &str = " INFO";
const WARN_STR: &str = " WARN";
const ERROR_STR: &str = "ERROR";

const TRACE_STYLE: Style = Style::new().fg(Color::Magenta);
const DEBUG_STYLE: Style = Style::new().fg(Color::Blue);
const INFO_STYLE: Style = Style::new().fg(Color::Green);
const WARN_STYLE: Style = Style::new().fg(Color::Yellow);
const ERROR_STYLE: Style = Style::new().fg(Color::Red);

impl std::fmt::Display for FmtLevel<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match *self.level {
            Level::TRACE => TRACE_STYLE.force_styling(self.ansi).apply_to(TRACE_STR),
            Level::DEBUG => DEBUG_STYLE.force_styling(self.ansi).apply_to(DEBUG_STR),
            Level::INFO => INFO_STYLE.force_styling(self.ansi).apply_to(INFO_STR),
            Level::WARN => WARN_STYLE.force_styling(self.ansi).apply_to(WARN_STR),
            Level::ERROR => ERROR_STYLE.force_styling(self.ansi).apply_to(ERROR_STR),
        };
        write!(f, "{msg}")
    }
}

struct TargetFmt<'a> {
    target: &'a str,
    line: Option<u32>,
}

impl<'a> TargetFmt<'a> {
    pub(crate) fn new(metadata: &tracing::Metadata<'a>) -> Self {
        Self {
            target: metadata.target(),
            line: metadata.line(),
        }
    }
}

impl std::fmt::Display for TargetFmt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.target)?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        Ok(())
    }
}

impl<S, N> FormatEvent<S, N> for EventFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let ansi = writer.has_ansi_escapes();
        let metadata = event.metadata();

        TIMER.format_time(&mut writer)?;

        let level = FmtLevel::new(metadata.level(), ansi);
        write!(&mut writer, " {level} ")?;

        // If there is no explicit 'name' set in the event macro, it will have the
        // 'event {filename}:{line}' value. In this case, we want to display the target:
        // the module from where it was emitted. In other cases, we want to
        // display the explit name of the event we have set.
        let style = Style::new().dim().force_styling(ansi);
        if metadata.name().starts_with("event ") {
            write!(&mut writer, "{} ", style.apply_to(TargetFmt::new(metadata)))?;
        } else {
            write!(&mut writer, "{} ", style.apply_to(metadata.name()))?;
        }

        LogContext::maybe_with(|log_context| {
            let log_context = Style::new()
                .bold()
                .force_styling(ansi)
                .apply_to(log_context);
            write!(&mut writer, "{log_context} - ")
        })
        .transpose()?;

        let field_fromatter = DefaultFields::new();
        field_fromatter.format_fields(writer.by_ref(), event)?;

        // If we have a OTEL span, we can add the trace ID to the end of the log line
        if let Some(trace_id) = current_trace_id(ctx)
            && trace_id != TraceId::INVALID
        {
            let label = Style::new()
                .italic()
                .force_styling(ansi)
                .apply_to("trace.id");
            write!(&mut writer, " {label}={trace_id}")?;
        }

        writeln!(&mut writer)
    }
}

/// Look up the OTEL trace ID for the event's current span, if any.
fn current_trace_id<S, N>(ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>) -> Option<TraceId>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    let span = ctx.lookup_current()?;
    tracing::dispatcher::get_default(|dispatch| {
        let otel_cx = get_otel_context(&span.id(), dispatch)?;
        Some(otel_cx.span().span_context().trace_id())
    })
}

/// An event formatter which writes one JSON object per line, including the log
/// context tag and the OTEL trace ID.
///
/// This is meant for machine consumption (e.g. ingestion into a log
/// aggregator). It carries the same information as [`EventFormatter`], but in a
/// structured form.
#[derive(Debug, Default)]
pub struct JsonEventFormatter;

/// A [`tracing::field::Visit`] implementation which collects fields into a JSON
/// object.
struct JsonVisitor<'a> {
    fields: &'a mut serde_json::Map<String, serde_json::Value>,
}

impl tracing::field::Visit for JsonVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fields
            .insert(field.name().to_owned(), serde_json::json!(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_owned(), serde_json::json!(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), serde_json::json!(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_owned(), serde_json::json!(value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), serde_json::json!(value));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.fields.insert(
            field.name().to_owned(),
            serde_json::json!(value.to_string()),
        );
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_owned(),
            serde_json::json!(format!("{value:?}")),
        );
    }
}

impl<S, N> FormatEvent<S, N> for JsonEventFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();

        let mut object = serde_json::Map::new();

        let mut timestamp = String::new();
        TIMER.format_time(&mut Writer::new(&mut timestamp))?;
        object.insert("timestamp".to_owned(), serde_json::json!(timestamp));

        object.insert(
            "level".to_owned(),
            serde_json::json!(metadata.level().as_str()),
        );

        // If there is an explicit 'name' set on the event, record it; otherwise
        // the name is the autogenerated 'event {file}:{line}', which isn't
        // useful, so we record the target (the emitting module) instead.
        if metadata.name().starts_with("event ") {
            object.insert("target".to_owned(), serde_json::json!(metadata.target()));
            if let Some(line) = metadata.line() {
                object.insert("line".to_owned(), serde_json::json!(line));
            }
        } else {
            object.insert("name".to_owned(), serde_json::json!(metadata.name()));
            object.insert("target".to_owned(), serde_json::json!(metadata.target()));
        }

        // Add the log context tag, if there is one
        LogContext::maybe_with(|log_context| {
            object.insert(
                "log_context".to_owned(),
                serde_json::json!(log_context.to_string()),
            );
        });

        // Add the OTEL trace ID, if there is a valid one
        if let Some(trace_id) = current_trace_id(ctx)
            && trace_id != TraceId::INVALID
        {
            object.insert(
                "trace_id".to_owned(),
                serde_json::json!(trace_id.to_string()),
            );
        }

        // Collect the event's fields (including the message) into a nested object
        let mut fields = serde_json::Map::new();
        let mut visitor = JsonVisitor {
            fields: &mut fields,
        };
        event.record(&mut visitor);
        object.insert("fields".to_owned(), serde_json::Value::Object(fields));

        let line = serde_json::to_string(&object).map_err(|_| std::fmt::Error)?;
        writeln!(&mut writer, "{line}")
    }
}
