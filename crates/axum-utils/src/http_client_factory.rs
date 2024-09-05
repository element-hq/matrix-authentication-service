// Copyright (C) 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use http_body_util::Full;
use hyper_util::rt::TokioExecutor;
use mas_http::{
    make_traced_connector, BodyToBytesResponseLayer, Client, ClientLayer, ClientService,
    HttpService, TracedClient, TracedConnector,
};
use tower::{
    util::{MapErrLayer, MapRequestLayer},
    BoxError, Layer,
};

#[derive(Debug, Clone)]
pub struct HttpClientFactory {
    traced_connector: TracedConnector,
    client_layer: ClientLayer,
}

impl Default for HttpClientFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClientFactory {
    /// Constructs a new HTTP client factory
    #[must_use]
    pub fn new() -> Self {
        Self {
            traced_connector: make_traced_connector(),
            client_layer: ClientLayer::new(),
        }
    }

    /// Constructs a new HTTP client
    pub fn client<B>(&self, category: &'static str) -> ClientService<TracedClient<B>>
    where
        B: axum::body::HttpBody + Send,
        B::Data: Send,
    {
        let client = Client::builder(TokioExecutor::new()).build(self.traced_connector.clone());
        self.client_layer
            .clone()
            .with_category(category)
            .layer(client)
    }

    /// Constructs a new [`HttpService`], suitable for `mas-oidc-client`
    pub fn http_service(&self, category: &'static str) -> HttpService {
        let client = self.client(category);
        let client = (
            MapErrLayer::new(BoxError::from),
            MapRequestLayer::new(|req: http::Request<_>| req.map(Full::new)),
            BodyToBytesResponseLayer,
        )
            .layer(client);

        HttpService::new(client)
    }
}
