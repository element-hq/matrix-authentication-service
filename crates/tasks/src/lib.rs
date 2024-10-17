// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::sync::Arc;

use apalis_core::{executor::TokioExecutor, layers::extensions::Extension, monitor::Monitor};
use mas_email::Mailer;
use mas_matrix::HomeserverConnection;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, RepositoryError, SystemClock};
use mas_storage_pg::PgRepository;
use new_queue::QueueRunnerError;
use rand::SeedableRng;
use sqlx::{Pool, Postgres};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::debug;

use crate::storage::PostgresStorageFactory;

mod database;
mod email;
mod matrix;
mod new_queue;
mod recovery;
mod storage;
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

    pub fn inject(&self) -> Extension<Self> {
        Extension(self.clone())
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

    pub async fn repository(&self) -> Result<BoxRepository, RepositoryError> {
        let repo = PgRepository::from_pool(self.pool())
            .await
            .map_err(RepositoryError::from_error)?
            .boxed();

        Ok(repo)
    }

    pub fn matrix_connection(&self) -> &dyn HomeserverConnection<Error = anyhow::Error> {
        self.homeserver.as_ref()
    }

    pub fn url_builder(&self) -> &UrlBuilder {
        &self.url_builder
    }
}

trait JobContextExt {
    fn state(&self) -> State;
}

impl JobContextExt for apalis_core::context::JobContext {
    fn state(&self) -> State {
        self.data_opt::<State>()
            .expect("state not injected in job context")
            .clone()
    }
}

/// Helper macro to build a storage-backed worker.
macro_rules! build {
    ($job:ty => $fn:ident, $suffix:expr, $state:expr, $factory:expr) => {{
        let storage = $factory.build();
        let worker_name = format!(
            "{job}-{suffix}",
            job = <$job as ::apalis_core::job::Job>::NAME,
            suffix = $suffix
        );

        let builder = ::apalis_core::builder::WorkerBuilder::new(worker_name)
            .layer($state.inject())
            .layer(crate::utils::trace_layer())
            .layer(crate::utils::metrics_layer());

        let builder = ::apalis_core::storage::builder::WithStorage::with_storage_config(
            builder,
            storage,
            |c| c.fetch_interval(std::time::Duration::from_secs(1)),
        );
        ::apalis_core::builder::WorkerFactory::build(builder, ::apalis_core::job_fn::job_fn($fn))
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
    cancellation_token: CancellationToken,
    task_tracker: &TaskTracker,
) -> Result<Monitor<TokioExecutor>, QueueRunnerError> {
    let state = State::new(
        pool.clone(),
        SystemClock::default(),
        mailer.clone(),
        homeserver,
        url_builder,
    );
    let factory = PostgresStorageFactory::new(pool.clone());
    let monitor = Monitor::new().executor(TokioExecutor::new());
    let monitor = self::database::register(name, monitor, &state);
    let monitor = self::email::register(name, monitor, &state, &factory);
    let monitor = self::matrix::register(name, monitor, &state, &factory);
    let monitor = self::user::register(name, monitor, &state, &factory);
    let monitor = self::recovery::register(name, monitor, &state, &factory);
    // TODO: we might want to grab the join handle here
    // TODO: this error isn't right, I just want that to compile
    factory
        .listen()
        .await
        .map_err(QueueRunnerError::SetupListener)?;
    debug!(?monitor, "workers registered");

    let mut worker = self::new_queue::QueueWorker::new(state, cancellation_token).await?;

    task_tracker.spawn(async move {
        if let Err(e) = worker.run().await {
            tracing::error!(
                error = &e as &dyn std::error::Error,
                "Failed to run new queue"
            );
        }
    });

    Ok(monitor)
}
