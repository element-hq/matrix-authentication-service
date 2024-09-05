// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Implements a transport for Sentry based on Hyper.
//!
//! This avoids the dependency on `reqwest`, which helps avoiding having two
//! HTTP and TLS stacks in the binary.
//!
//! The [`ratelimit`] and [`tokio_thread`] modules are directly copied from the
//! Sentry codebase.

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{header::RETRY_AFTER, StatusCode};
use mas_http::UntracedClient;
use sentry::{sentry_debug, ClientOptions, Transport, TransportFactory};

use self::tokio_thread::TransportThread;

mod ratelimit;
mod tokio_thread;

pub struct HyperTransport {
    thread: TransportThread,
}

pub struct HyperTransportFactory {
    client: UntracedClient<Full<Bytes>>,
}

impl HyperTransportFactory {
    pub fn new(client: UntracedClient<Full<Bytes>>) -> Self {
        Self { client }
    }
}

impl TransportFactory for HyperTransportFactory {
    fn create_transport(&self, options: &ClientOptions) -> Arc<dyn Transport> {
        Arc::new(HyperTransport::new(options, self.client.clone()))
    }
}

impl HyperTransport {
    pub fn new(options: &ClientOptions, client: UntracedClient<Full<Bytes>>) -> Self {
        let dsn = options.dsn.as_ref().unwrap();
        let user_agent = options.user_agent.clone();
        let auth = dsn.to_auth(Some(&user_agent)).to_string();
        let url = dsn.envelope_api_url().to_string();

        let thread = TransportThread::new(move |envelope, mut rl| {
            let mut body = Vec::new();
            envelope.to_writer(&mut body).unwrap();

            let request = hyper::Request::post(&url)
                .header("X-Sentry-Auth", &auth)
                .body(Full::new(Bytes::from(body)))
                .unwrap();

            let fut = client.request(request);

            async move {
                match fut.await {
                    Ok(response) => {
                        if let Some(sentry_header) = response
                            .headers()
                            .get("x-sentry-rate-limits")
                            .and_then(|x| x.to_str().ok())
                        {
                            rl.update_from_sentry_header(sentry_header);
                        } else if let Some(retry_after) = response
                            .headers()
                            .get(RETRY_AFTER)
                            .and_then(|x| x.to_str().ok())
                        {
                            rl.update_from_retry_after(retry_after);
                        } else if response.status() == StatusCode::TOO_MANY_REQUESTS {
                            rl.update_from_429();
                        }

                        match response.into_body().collect().await {
                            Err(err) => {
                                sentry_debug!("Failed to read sentry response: {}", err);
                            }
                            Ok(body) => {
                                let body = body.to_bytes();
                                let text = String::from_utf8_lossy(&body);
                                sentry_debug!("Get response: `{}`", text);
                            }
                        }
                    }
                    Err(err) => {
                        sentry_debug!("Failed to send envelope: {}", err);
                    }
                }

                rl
            }
        });

        Self { thread }
    }
}

impl Transport for HyperTransport {
    fn send_envelope(&self, envelope: sentry::Envelope) {
        self.thread.send(envelope);
    }

    fn flush(&self, timeout: Duration) -> bool {
        self.thread.flush(timeout)
    }

    fn shutdown(&self, timeout: Duration) -> bool {
        self.flush(timeout)
    }
}
