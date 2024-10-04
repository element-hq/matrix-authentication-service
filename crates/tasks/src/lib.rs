// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{marker::Sync, sync::Arc};

use apalis::{
    prelude::{Data, Request},
    utils::TokioExecutor,
};
use apalis_core::{builder::WorkerBuilder, layers::Identity, monitor::Monitor};
use apalis_sql::{
    context::SqlContext,
    postgres::{PgListen, PostgresStorage},
};
use mas_email::Mailer;
use mas_matrix::HomeserverConnection;
use mas_router::UrlBuilder;
use mas_storage::{job::TaskNamespace, BoxClock, BoxRepository, SystemClock};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::SeedableRng;
use serde::{de::DeserializeOwned, ser::Serialize};
use sqlx::{Pool, Postgres};
use tower::{layer::util::Stack, Service};
use tracing::{debug, error};

mod database;
mod email;
mod matrix;
mod recovery;
mod user;
mod utils;

use self::utils::{metrics_layer, trace_layer, MetricsLayerForJob, TraceLayerForJob, TracedJob};

type LayerForJob<T, C = SqlContext> = (
    Data<State>,
    MetricsLayerForJob<T, C>,
    TraceLayerForJob<T, C>,
);

#[derive(Clone)]
struct State {
    suffix: String,
    pool: Pool<Postgres>,
    mailer: Mailer,
    clock: SystemClock,
    homeserver: Arc<dyn HomeserverConnection<Error = anyhow::Error>>,
    url_builder: UrlBuilder,
}

impl State {
    pub fn new(
        suffix: &str,
        pool: Pool<Postgres>,
        clock: SystemClock,
        mailer: Mailer,
        homeserver: impl HomeserverConnection<Error = anyhow::Error> + 'static,
        url_builder: UrlBuilder,
    ) -> Self {
        Self {
            suffix: suffix.to_owned(),
            pool,
            mailer,
            clock,
            homeserver: Arc::new(homeserver),
            url_builder,
        }
    }

    pub fn worker_name<T: TaskNamespace>(&self) -> String {
        format!("{}-{}", T::NAMESPACE, self.suffix)
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

    pub fn pg_worker<T, S>(
        &self,
        listener: &mut PgListen,
    ) -> apalis_core::builder::WorkerBuilder<
        T,
        SqlContext,
        PostgresStorage<T>,
        Stack<LayerForJob<T>, Identity>,
        S,
    >
    where
        T: TaskNamespace + TracedJob + Serialize + DeserializeOwned + Send + Sync + Unpin + 'static,
        S: Service<Request<T, SqlContext>> + Send + Sync + 'static,
        S::Response: Send + Sync + 'static,
    {
        let pool = self.pool();
        let worker_name = self.worker_name::<T>();
        let config = apalis_sql::Config::new(T::NAMESPACE)
            .set_poll_interval(std::time::Duration::from_secs(10));
        let mut pg = apalis_sql::postgres::PostgresStorage::new_with_config(pool.clone(), config);
        {
            let mut pg = pg.clone();
            tokio::spawn(async move {
                pg.reenqueue_orphaned(5).await.unwrap();
            });
        }
        listener.subscribe_with(&mut pg);

        WorkerBuilder::new(worker_name)
            .layer((Data::new(self.clone()), metrics_layer(), trace_layer()))
            .backend(pg)
    }
}

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
        name,
        pool.clone(),
        SystemClock::default(),
        mailer.clone(),
        homeserver,
        url_builder,
    );
    let mut listener = PgListen::new(pool.clone()).await?;
    let monitor = Monitor::new();
    let monitor = self::database::register(monitor, &state);
    let monitor = self::email::register(monitor, &state, &mut listener);
    let monitor = self::matrix::register(monitor, &state, &mut listener);
    let monitor = self::user::register(monitor, &state, &mut listener);
    let monitor = self::recovery::register(monitor, &state, &mut listener);
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
