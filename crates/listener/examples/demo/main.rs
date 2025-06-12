// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    convert::Infallible,
    io::BufReader,
    net::{Ipv4Addr, TcpListener},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use hyper::{Request, Response};
use mas_listener::{ConnectionInfo, server::Server};
use tokio_rustls::rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use tokio_util::sync::CancellationToken;
use tower::service_fn;

static CA_CERT_PEM: &[u8] = include_bytes!("./certs/ca.pem");
static SERVER_CERT_PEM: &[u8] = include_bytes!("./certs/server.pem");
static SERVER_KEY_PEM: &[u8] = include_bytes!("./certs/server-key.pem");

async fn handler(req: Request<hyper::body::Incoming>) -> Result<Response<String>, Infallible> {
    tracing::info!("Handling request");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let info = req.extensions().get::<ConnectionInfo>().unwrap();
    let body = format!("{info:?}");
    Ok(Response::new(body))
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();

    let tls_config = load_tls_config()?;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 3000))?;
    let proxy_protocol_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 3001))?;
    let tls_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 3002))?;
    let tls_proxy_protocol_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 3003))?;

    let servers = vec![
        Server::try_new(listener, service_fn(handler))?,
        Server::try_new(proxy_protocol_listener, service_fn(handler))?.with_proxy(),
        Server::try_new(tls_listener, service_fn(handler))?.with_tls(tls_config.clone()),
        Server::try_new(tls_proxy_protocol_listener, service_fn(handler))?
            .with_proxy()
            .with_tls(tls_config.clone()),
    ];

    tracing::info!(
        "Listening on http://127.0.0.1:3000, http(proxy)://127.0.0.1:3001, https://127.0.0.1:3002 and https(proxy)://127.0.0.1:3003"
    );

    let hard_shutdown = CancellationToken::new();
    let soft_shutdown = hard_shutdown.child_token();

    {
        let hard_shutdown = hard_shutdown.clone();
        let soft_shutdown = soft_shutdown.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.unwrap();
            tracing::info!("Ctrl-C received, performing soft-shutdown");
            soft_shutdown.cancel();
            tokio::signal::ctrl_c().await.unwrap();
            tracing::info!("Ctrl-C received again, shutting down");
            hard_shutdown.cancel();
        });
    }

    mas_listener::server::run_servers(servers, hard_shutdown, soft_shutdown).await;

    Ok(())
}

fn load_tls_config() -> Result<Arc<ServerConfig>, anyhow::Error> {
    let mut ca_cert_reader = BufReader::new(CA_CERT_PEM);
    let ca_cert = rustls_pemfile::certs(&mut ca_cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid CA certificate")?;
    let mut ca_cert_store = RootCertStore::empty();
    ca_cert_store.add_parsable_certificates(ca_cert);

    let mut server_cert_reader = BufReader::new(SERVER_CERT_PEM);
    let server_cert: Vec<_> = rustls_pemfile::certs(&mut server_cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid server certificate")?;

    let mut server_key_reader = BufReader::new(SERVER_KEY_PEM);
    let server_key = rustls_pemfile::rsa_private_keys(&mut server_key_reader)
        .next()
        .context("No RSA private key found")?
        .context("Invalid server TLS keys")?;

    let client_cert_verifier = WebPkiClientVerifier::builder(Arc::new(ca_cert_store))
        .allow_unauthenticated()
        .build()?;

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(server_cert, server_key.into())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}
