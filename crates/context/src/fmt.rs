// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use console::{Color, Style};
use opentelemetry::{TraceId, trace::TraceContextExt};
use tracing::{Level, Subscriber};
use tracing_opentelemetry::OtelData;
use tracing_subscriber::{
    fmt::{
        FormatEvent, FormatFields,
        format::{DefaultFields, Writer},
        time::{FormatTime, SystemTime},
    },
    registry::LookupSpan,
};

use crate::LogContext;

/// An event formatter usable by the [`tracing-subscriber`] crate, which
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

        SystemTime.format_time(&mut writer)?;

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

        if let Some(log_context) = LogContext::current() {
            let log_context = Style::new()
                .bold()
                .force_styling(ansi)
                .apply_to(log_context);
            write!(&mut writer, "{log_context} - ")?;
        }

        let field_fromatter = DefaultFields::new();
        field_fromatter.format_fields(writer.by_ref(), event)?;

        // If we have a OTEL span, we can add the trace ID to the end of the log line
        if let Some(span) = ctx.lookup_current() {
            if let Some(otel) = span.extensions().get::<OtelData>() {
                // If it is the root span, the trace ID will be in the span builder. Else, it
                // will be in the parent OTEL context
                let trace_id = otel
                    .builder
                    .trace_id
                    .unwrap_or_else(|| otel.parent_cx.span().span_context().trace_id());
                if trace_id != TraceId::INVALID {
                    let label = Style::new()
                        .italic()
                        .force_styling(ansi)
                        .apply_to("trace.id");
                    write!(&mut writer, " {label}={trace_id}")?;
                }
            }
        }

        writeln!(&mut writer)
    }
}
