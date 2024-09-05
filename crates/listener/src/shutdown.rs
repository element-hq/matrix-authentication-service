// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{fmt::Display, pin::Pin, task::Poll, time::Duration};

use futures_util::{ready, Future, Stream};
use tokio::{
    signal::unix::{signal, Signal, SignalKind},
    time::Sleep,
};

#[derive(Debug, Clone, Copy)]
pub enum ShutdownReason {
    Signal(SignalKind),
    Timeout,
}

fn signal_to_str(kind: SignalKind) -> &'static str {
    match kind.as_raw_value() {
        libc::SIGALRM => "SIGALRM",
        libc::SIGCHLD => "SIGCHLD",
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGIO => "SIGIO",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGTERM => "SIGTERM",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGUSR2 => "SIGUSR2",
        _ => "SIG???",
    }
}

impl Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signal(s) => signal_to_str(*s).fmt(f),
            Self::Timeout => "timeout".fmt(f),
        }
    }
}

pub enum ShutdownStreamState {
    Waiting,

    Graceful { sleep: Option<Pin<Box<Sleep>>> },

    Done,
}

impl Default for ShutdownStreamState {
    fn default() -> Self {
        Self::Waiting
    }
}

impl ShutdownStreamState {
    fn is_graceful(&self) -> bool {
        matches!(self, Self::Graceful { .. })
    }

    fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }

    fn get_sleep_mut(&mut self) -> Option<&mut Pin<Box<Sleep>>> {
        match self {
            Self::Graceful { sleep } => sleep.as_mut(),
            _ => None,
        }
    }
}

/// A stream which is used to drive a graceful shutdown.
///
/// It will emit 2 items: one when a first signal is caught, the other when
/// either another signal is caught, or after a timeout.
#[derive(Default)]
pub struct ShutdownStream {
    state: ShutdownStreamState,
    signals: Vec<(SignalKind, Signal)>,
    timeout: Option<Duration>,
}

impl ShutdownStream {
    /// Create a default shutdown stream, which listens on SIGINT and SIGTERM,
    /// with a 60s timeout
    ///
    /// # Errors
    ///
    /// Returns an error if signal handlers could not be installed
    pub fn new() -> Result<Self, std::io::Error> {
        let ret = Self::default()
            .with_timeout(Duration::from_secs(60))
            .with_signal(SignalKind::interrupt())?
            .with_signal(SignalKind::terminate())?;

        Ok(ret)
    }

    /// Add a signal to register
    ///
    /// # Errors
    ///
    /// Returns an error if the signal handler could not be installed
    pub fn with_signal(mut self, kind: SignalKind) -> Result<Self, std::io::Error> {
        let signal = signal(kind)?;
        self.signals.push((kind, signal));
        Ok(self)
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl Stream for ShutdownStream {
    type Item = ShutdownReason;

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.state {
            ShutdownStreamState::Waiting => (2, Some(2)),
            ShutdownStreamState::Graceful { .. } => (1, Some(1)),
            ShutdownStreamState::Done => (0, Some(0)),
        }
    }

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.state.is_done() {
            return Poll::Ready(None);
        }

        for (kind, signal) in &mut this.signals {
            match signal.poll_recv(cx) {
                Poll::Ready(_) => {
                    // We got a signal
                    if this.state.is_graceful() {
                        // If we was gracefully shutting down, mark it as done
                        this.state = ShutdownStreamState::Done;
                    } else {
                        // Else start the timeout
                        let sleep = this
                            .timeout
                            .map(|duration| Box::pin(tokio::time::sleep(duration)));
                        this.state = ShutdownStreamState::Graceful { sleep };
                    }

                    return Poll::Ready(Some(ShutdownReason::Signal(*kind)));
                }
                Poll::Pending => {}
            }
        }

        if let Some(timeout) = this.state.get_sleep_mut() {
            ready!(timeout.as_mut().poll(cx));
            this.state = ShutdownStreamState::Done;
            Poll::Ready(Some(ShutdownReason::Timeout))
        } else {
            Poll::Pending
        }
    }
}
