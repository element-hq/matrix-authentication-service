// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::sync::{Arc, LazyLock};

use mas_email::Mailer;
use mas_matrix::HomeserverConnection;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, RepositoryError, SystemClock};
use mas_storage_pg::PgRepository;
use new_queue::QueueRunnerError;
use opentelemetry::metrics::Meter;
use rand::SeedableRng;
use sqlx::{Pool, Postgres};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

mod database;
mod email;
mod matrix;
mod new_queue;
mod recovery;
mod user;

static METER: LazyLock<Meter> = LazyLock::new(|| {
    let scope = opentelemetry::InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(opentelemetry_semantic_conventions::SCHEMA_URL)
        .build();

    opentelemetry::global::meter_with_scope(scope)
});

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

/// Initialise the workers.
///
/// # Errors
///
/// This function can fail if the database connection fails.
pub async fn init(
    pool: &Pool<Postgres>,
    mailer: &Mailer,
    homeserver: impl HomeserverConnection<Error = anyhow::Error> + 'static,
    url_builder: UrlBuilder,
    cancellation_token: CancellationToken,
    task_tracker: &TaskTracker,
) -> Result<(), QueueRunnerError> {
    let state = State::new(
        pool.clone(),
        SystemClock::default(),
        mailer.clone(),
        homeserver,
        url_builder,
    );
    let mut worker = self::new_queue::QueueWorker::new(state, cancellation_token).await?;

    worker
        .register_handler::<mas_storage::queue::CleanupExpiredTokensJob>()
        .register_handler::<mas_storage::queue::DeactivateUserJob>()
        .register_handler::<mas_storage::queue::DeleteDeviceJob>()
        .register_handler::<mas_storage::queue::ProvisionDeviceJob>()
        .register_handler::<mas_storage::queue::ProvisionUserJob>()
        .register_handler::<mas_storage::queue::ReactivateUserJob>()
        .register_handler::<mas_storage::queue::SendAccountRecoveryEmailsJob>()
        .register_handler::<mas_storage::queue::SyncDevicesJob>()
        .register_handler::<mas_storage::queue::VerifyEmailJob>()
        .add_schedule(
            "cleanup-expired-tokens",
            "0 0 * * * *".parse()?,
            mas_storage::queue::CleanupExpiredTokensJob,
        );

    task_tracker.spawn(worker.run());

    Ok(())
}
