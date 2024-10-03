// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::sync::Arc;

use apalis::utils::TokioExecutor;
use apalis_core::monitor::Monitor;
use apalis_sql::postgres::PgListen;
use mas_email::Mailer;
use mas_matrix::HomeserverConnection;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, SystemClock};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::SeedableRng;
use sqlx::{Pool, Postgres};
use tracing::{debug, error};

mod database;
mod email;
mod matrix;
mod recovery;
mod user;
mod utils;

#[derive(Clone)]
struct State {
    pool: Pool<Postgres>,
    mailer: Mailer,
    clock: SystemClock,
    homeserver: Arc<dyn HomeserverConnection<Error = anyhow::Error>>,
    url_builder: UrlBuilder,
}

impl State {
    pub fn new(
        pool: Pool<Postgres>,
        clock: SystemClock,
        mailer: Mailer,
        homeserver: impl HomeserverConnection<Error = anyhow::Error> + 'static,
        url_builder: UrlBuilder,
    ) -> Self {
        Self {
            pool,
            mailer,
            clock,
            homeserver: Arc::new(homeserver),
            url_builder,
        }
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    pub fn clock(&self) -> BoxClock {
        Box::new(self.clock.clone())
    }

    pub fn mailer(&self) -> &Mailer {
        &self.mailer
    }

    // This is fine for now, we may move that to a trait at some point.
    #[allow(clippy::unused_self, clippy::disallowed_methods)]
    pub fn rng(&self) -> rand_chacha::ChaChaRng {
        rand_chacha::ChaChaRng::from_rng(rand::thread_rng()).expect("failed to seed rng")
    }

    pub async fn repository(&self) -> Result<BoxRepository, DatabaseError> {
        let repo = PgRepository::from_pool(self.pool()).await?.boxed();

        Ok(repo)
    }

    pub fn matrix_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error> {
        self.homeserver.as_ref()
    }

    pub fn url_builder(&self) -> &UrlBuilder {
        &self.url_builder
    }
}

/// Helper macro to build a storage-backed worker.
macro_rules! build {
    ($job:ty => $fn:ident, $suffix:expr, $state:expr, $pool:expr, $listener:expr) => {{
        use ::apalis_core::builder::WorkerFactory;
        let namespace = <$job as ::mas_storage::job::TaskNamespace>::NAMESPACE;
        let config = ::apalis_sql::Config::new(namespace)
            .set_poll_interval(std::time::Duration::from_secs(10));
        let mut pg = ::apalis_sql::postgres::PostgresStorage::new_with_config($pool, config);
        $listener.subscribe_with(&mut pg);
        let worker_name = format!("{job}-{suffix}", job = namespace, suffix = $suffix);

        ::apalis_core::builder::WorkerBuilder::new(worker_name)
            .data($state.clone())
            .layer(crate::utils::trace_layer())
            .layer(crate::utils::metrics_layer())
            .backend(pg)
            .build(::apalis_core::service_fn::service_fn($fn))
    }};
}

pub(crate) use build;

/// Initialise the workers.
///
/// # Errors
///
/// This function can fail if the database connection fails.
pub async fn init(
    name: &str,
    pool: &Pool<Postgres>,
    mailer: &Mailer,
    homeserver: impl HomeserverConnection<Error = anyhow::Error> + 'static,
    url_builder: UrlBuilder,
) -> Result<Monitor<TokioExecutor>, sqlx::Error> {
    let state = State::new(
        pool.clone(),
        SystemClock::default(),
        mailer.clone(),
        homeserver,
        url_builder,
    );
    let mut listener = PgListen::new(pool.clone()).await?;
    let monitor = Monitor::new();
    let monitor = self::database::register(name, monitor, &state);
    let monitor = self::email::register(name, monitor, &state, &mut listener, pool.clone());
    let monitor = self::matrix::register(name, monitor, &state, &mut listener, pool.clone());
    let monitor = self::user::register(name, monitor, &state, &mut listener, pool.clone());
    let monitor = self::recovery::register(name, monitor, &state, &mut listener, pool.clone());
    // TODO: we might want to grab the join handle here
    tokio::spawn(async {
        if let Err(e) = listener.listen().await {
            error!(
                error = &e as &dyn std::error::Error,
                "Task listener crashed",
            );
        }
    });

    debug!(?monitor, "workers registered");
    Ok(monitor)
}
