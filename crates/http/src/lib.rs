// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! [`tower`] layers and services to help building HTTP client and servers

#![deny(rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]

mod client;
mod ext;
mod layers;
mod reqwest;
mod service;

pub use self::{
    client::{
        make_traced_connector, make_untraced_client, Client, TracedClient, TracedConnector,
        UntracedClient, UntracedConnector,
    },
    ext::{set_propagator, CorsLayerExt, ServiceExt as HttpServiceExt},
    layers::{
        body_to_bytes_response::{self, BodyToBytesResponse, BodyToBytesResponseLayer},
        bytes_to_body_request::{self, BytesToBodyRequest, BytesToBodyRequestLayer},
        catch_http_codes::{self, CatchHttpCodes, CatchHttpCodesLayer},
        client::{ClientLayer, ClientService},
        form_urlencoded_request::{self, FormUrlencodedRequest, FormUrlencodedRequestLayer},
        json_request::{self, JsonRequest, JsonRequestLayer},
        json_response::{self, JsonResponse, JsonResponseLayer},
    },
    reqwest::{client as reqwest_client, RequestBuilderExt},
    service::{BoxCloneSyncService, HttpService},
};

pub type EmptyBody = http_body_util::Empty<bytes::Bytes>;
