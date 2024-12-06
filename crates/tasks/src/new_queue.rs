// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_storage::{
    queue::{InsertableJob, Job, JobMetadata, Worker},
    Clock, RepositoryAccess, RepositoryError,
};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::{distributions::Uniform, Rng, RngCore};
use rand_chacha::ChaChaRng;
use serde::de::DeserializeOwned;
use sqlx::{
    postgres::{PgAdvisoryLock, PgListener},
    Acquire, Either,
};
use thiserror::Error;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use ulid::Ulid;

use crate::State;

type JobPayload = serde_json::Value;

#[derive(Clone)]
pub struct JobContext {
    pub id: Ulid,
    pub metadata: JobMetadata,
    pub queue_name: String,
    pub attempt: usize,
    pub cancellation_token: CancellationToken,
}

impl JobContext {
    pub fn span(&self) -> Span {
        let span = tracing::info_span!(
            parent: Span::none(),
            "job.run",
            job.id = %self.id,
            job.queue_name = self.queue_name,
            job.attempt = self.attempt,
        );

        span.add_link(self.metadata.span_context());

        span
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JobErrorDecision {
    Retry,

    #[default]
    Fail,
}

impl std::fmt::Display for JobErrorDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry => f.write_str("retry"),
            Self::Fail => f.write_str("fail"),
        }
    }
}

#[derive(Debug, Error)]
#[error("Job failed to run, will {decision}")]
pub struct JobError {
    decision: JobErrorDecision,
    #[source]
    error: anyhow::Error,
}

impl JobError {
    pub fn retry<T: Into<anyhow::Error>>(error: T) -> Self {
        Self {
            decision: JobErrorDecision::Retry,
            error: error.into(),
        }
    }

    pub fn fail<T: Into<anyhow::Error>>(error: T) -> Self {
        Self {
            decision: JobErrorDecision::Fail,
            error: error.into(),
        }
    }
}

pub trait FromJob {
    fn from_job(payload: JobPayload) -> Result<Self, anyhow::Error>
    where
        Self: Sized;
}

impl<T> FromJob for T
where
    T: DeserializeOwned,
{
    fn from_job(payload: JobPayload) -> Result<Self, anyhow::Error> {
        serde_json::from_value(payload).map_err(Into::into)
    }
}

#[async_trait]
pub trait RunnableJob: FromJob + Send + 'static {
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError>;
}

fn box_runnable_job<T: RunnableJob + 'static>(job: T) -> Box<dyn RunnableJob> {
    Box::new(job)
}

#[derive(Debug, Error)]
pub enum QueueRunnerError {
    #[error("Failed to setup listener")]
    SetupListener(#[source] sqlx::Error),

    #[error("Failed to start transaction")]
    StartTransaction(#[source] sqlx::Error),

    #[error("Failed to commit transaction")]
    CommitTransaction(#[source] sqlx::Error),

    #[error("Failed to acquire leader lock")]
    LeaderLock(#[source] sqlx::Error),

    #[error(transparent)]
    Repository(#[from] RepositoryError),

    #[error(transparent)]
    Database(#[from] DatabaseError),

    #[error("Worker is not the leader")]
    NotLeader,
}

// When the worker waits for a notification, we still want to wake it up every
// second. Because we don't want all the workers to wake up at the same time, we
// add a random jitter to the sleep duration, so they effectively sleep between
// 0.9 and 1.1 seconds.
const MIN_SLEEP_DURATION: std::time::Duration = std::time::Duration::from_millis(900);
const MAX_SLEEP_DURATION: std::time::Duration = std::time::Duration::from_millis(1100);

// How many jobs can we run concurrently
const MAX_CONCURRENT_JOBS: usize = 10;

// How many jobs can we fetch at once
const MAX_JOBS_TO_FETCH: usize = 5;

// How many attempts a job should be retried
const MAX_ATTEMPTS: usize = 5;

type JobResult = Result<(), JobError>;
type JobFactory = Arc<dyn Fn(JobPayload) -> Box<dyn RunnableJob> + Send + Sync>;

pub struct QueueWorker {
    rng: ChaChaRng,
    clock: Box<dyn Clock + Send>,
    listener: PgListener,
    registration: Worker,
    am_i_leader: bool,
    last_heartbeat: DateTime<Utc>,
    cancellation_token: CancellationToken,
    state: State,
    tracker: JobTracker,
}

impl QueueWorker {
    #[tracing::instrument(
        name = "worker.init",
        skip_all,
        fields(worker.id)
    )]
    pub async fn new(
        state: State,
        cancellation_token: CancellationToken,
    ) -> Result<Self, QueueRunnerError> {
        let mut rng = state.rng();
        let clock = state.clock();

        let mut listener = PgListener::connect_with(state.pool())
            .await
            .map_err(QueueRunnerError::SetupListener)?;

        // We get notifications of leader stepping down on this channel
        listener
            .listen("queue_leader_stepdown")
            .await
            .map_err(QueueRunnerError::SetupListener)?;

        // We get notifications when a job is available on this channel
        listener
            .listen("queue_available")
            .await
            .map_err(QueueRunnerError::SetupListener)?;

        let txn = listener
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;
        let mut repo = PgRepository::from_conn(txn);

        let registration = repo.queue_worker().register(&mut rng, &clock).await?;
        tracing::Span::current().record("worker.id", tracing::field::display(registration.id));
        repo.into_inner()
            .commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        tracing::info!("Registered worker");
        let now = clock.now();

        Ok(Self {
            rng,
            clock,
            listener,
            registration,
            am_i_leader: false,
            last_heartbeat: now,
            cancellation_token,
            state,
            tracker: JobTracker::default(),
        })
    }

    pub fn register_handler<T: RunnableJob + InsertableJob>(&mut self) -> &mut Self {
        // There is a potential panic here, which is fine as it's going to be caught
        // within the job task
        let factory = |payload: JobPayload| {
            box_runnable_job(T::from_job(payload).expect("Failed to deserialize job"))
        };

        self.tracker
            .factories
            .insert(T::QUEUE_NAME, Arc::new(factory));
        self
    }

    pub async fn run(&mut self) -> Result<(), QueueRunnerError> {
        while !self.cancellation_token.is_cancelled() {
            self.run_loop().await?;
        }

        self.shutdown().await?;

        Ok(())
    }

    #[tracing::instrument(name = "worker.run_loop", skip_all, err)]
    async fn run_loop(&mut self) -> Result<(), QueueRunnerError> {
        self.wait_until_wakeup().await?;

        if self.cancellation_token.is_cancelled() {
            return Ok(());
        }

        self.tick().await?;

        if self.am_i_leader {
            self.perform_leader_duties().await?;
        }

        Ok(())
    }

    #[tracing::instrument(name = "worker.shutdown", skip_all, err)]
    async fn shutdown(&mut self) -> Result<(), QueueRunnerError> {
        tracing::info!("Shutting down worker");

        // Start a transaction on the existing PgListener connection
        let txn = self
            .listener
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;

        let mut repo = PgRepository::from_conn(txn);

        // Log about any job still running
        match self.tracker.running_jobs() {
            0 => {}
            1 => tracing::warn!("There is one job still running, waiting for it to finish"),
            n => tracing::warn!("There are {n} jobs still running, waiting for them to finish"),
        }

        // TODO: we may want to introduce a timeout here, and abort the tasks if they
        // take too long. It's fine for now, as we don't have long-running
        // tasks, most of them are idempotent, and the only effect might be that
        // the worker would 'dirtily' shutdown, meaning that its tasks would be
        // considered, later retried by another worker

        // Wait for all the jobs to finish
        self.tracker
            .process_jobs(&mut self.rng, &self.clock, &mut repo, true)
            .await?;

        // Tell the other workers we're shutting down
        // This also releases the leader election lease
        repo.queue_worker()
            .shutdown(&self.clock, &self.registration)
            .await?;

        repo.into_inner()
            .commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        Ok(())
    }

    #[tracing::instrument(name = "worker.wait_until_wakeup", skip_all, err)]
    async fn wait_until_wakeup(&mut self) -> Result<(), QueueRunnerError> {
        // This is to make sure we wake up every second to do the maintenance tasks
        // We add a little bit of random jitter to the duration, so that we don't get
        // fully synced workers waking up at the same time after each notification
        let sleep_duration = self
            .rng
            .sample(Uniform::new(MIN_SLEEP_DURATION, MAX_SLEEP_DURATION));
        let wakeup_sleep = tokio::time::sleep(sleep_duration);

        // TODO: add metrics to track the wake up reasons

        tokio::select! {
            () = self.cancellation_token.cancelled() => {
                tracing::debug!("Woke up from cancellation");
            },

            () = wakeup_sleep => {
                tracing::debug!("Woke up from sleep");
            },

            () = self.tracker.collect_next_job(), if self.tracker.has_jobs() => {
                tracing::debug!("Joined job task");
            },

            notification = self.listener.recv() => {
                match notification {
                    Ok(notification) => {
                        tracing::debug!(
                            notification.channel = notification.channel(),
                            notification.payload = notification.payload(),
                            "Woke up from notification"
                        );
                    },
                    Err(e) => {
                        tracing::error!(error = &e as &dyn std::error::Error, "Failed to receive notification");
                    },
                }
            },
        }

        Ok(())
    }

    #[tracing::instrument(
        name = "worker.tick",
        skip_all,
        fields(worker.id = %self.registration.id),
        err,
    )]
    async fn tick(&mut self) -> Result<(), QueueRunnerError> {
        tracing::debug!("Tick");
        let now = self.clock.now();

        // Start a transaction on the existing PgListener connection
        let txn = self
            .listener
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;
        let mut repo = PgRepository::from_conn(txn);

        // We send a heartbeat every minute, to avoid writing to the database too often
        // on a logged table
        if now - self.last_heartbeat >= chrono::Duration::minutes(1) {
            tracing::info!("Sending heartbeat");
            repo.queue_worker()
                .heartbeat(&self.clock, &self.registration)
                .await?;
            self.last_heartbeat = now;
        }

        // Remove any dead worker leader leases
        repo.queue_worker()
            .remove_leader_lease_if_expired(&self.clock)
            .await?;

        // Try to become (or stay) the leader
        let leader = repo
            .queue_worker()
            .try_get_leader_lease(&self.clock, &self.registration)
            .await?;

        // Process any job task which finished
        self.tracker
            .process_jobs(&mut self.rng, &self.clock, &mut repo, false)
            .await?;

        // Compute how many jobs we should fetch at most
        let max_jobs_to_fetch = MAX_CONCURRENT_JOBS
            .saturating_sub(self.tracker.running_jobs())
            .max(MAX_JOBS_TO_FETCH);

        if max_jobs_to_fetch == 0 {
            tracing::warn!("Internal job queue is full, not fetching any new jobs");
        } else {
            // Grab a few jobs in the queue
            let queues = self.tracker.queues();
            let jobs = repo
                .queue_job()
                .reserve(&self.clock, &self.registration, &queues, max_jobs_to_fetch)
                .await?;

            for Job {
                id,
                queue_name,
                payload,
                metadata,
                attempt,
            } in jobs
            {
                let cancellation_token = self.cancellation_token.child_token();
                let context = JobContext {
                    id,
                    metadata,
                    queue_name,
                    attempt,
                    cancellation_token,
                };

                self.tracker.spawn_job(self.state.clone(), context, payload);
            }
        }

        // After this point, we are locking the leader table, so it's important that we
        // commit as soon as possible to not block the other workers for too long
        repo.into_inner()
            .commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        // Save the new leader state to log any change
        if leader != self.am_i_leader {
            // If we flipped state, log it
            self.am_i_leader = leader;
            if self.am_i_leader {
                tracing::info!("I'm the leader now");
            } else {
                tracing::warn!("I am no longer the leader");
            }
        }

        Ok(())
    }

    #[tracing::instrument(name = "worker.perform_leader_duties", skip_all, err)]
    async fn perform_leader_duties(&mut self) -> Result<(), QueueRunnerError> {
        // This should have been checked by the caller, but better safe than sorry
        if !self.am_i_leader {
            return Err(QueueRunnerError::NotLeader);
        }

        // Start a transaction on the existing PgListener connection
        let txn = self
            .listener
            .begin()
            .await
            .map_err(QueueRunnerError::StartTransaction)?;

        // The thing with the leader election is that it locks the table during the
        // election, preventing other workers from going through the loop.
        //
        // Ideally, we would do the leader duties in the same transaction so that we
        // make sure only one worker is doing the leader duties, but that
        // would mean we would lock all the workers for the duration of the
        // duties, which is not ideal.
        //
        // So we do the duties in a separate transaction, in which we take an advisory
        // lock, so that in the very rare case where two workers think they are the
        // leader, we still don't have two workers doing the duties at the same time.
        let lock = PgAdvisoryLock::new("leader-duties");

        let locked = lock
            .try_acquire(txn)
            .await
            .map_err(QueueRunnerError::LeaderLock)?;

        let locked = match locked {
            Either::Left(locked) => locked,
            Either::Right(txn) => {
                tracing::error!("Another worker has the leader lock, aborting");
                txn.rollback()
                    .await
                    .map_err(QueueRunnerError::CommitTransaction)?;
                return Ok(());
            }
        };

        let mut repo = PgRepository::from_conn(locked);

        // We also check if the worker is dead, and if so, we shutdown all the dead
        // workers that haven't checked in the last two minutes
        repo.queue_worker()
            .shutdown_dead_workers(&self.clock, Duration::minutes(2))
            .await?;

        // TODO: mark tasks those workers had as lost

        // Release the leader lock
        let txn = repo
            .into_inner()
            .release_now()
            .await
            .map_err(QueueRunnerError::LeaderLock)?;

        txn.commit()
            .await
            .map_err(QueueRunnerError::CommitTransaction)?;

        Ok(())
    }
}

/// Tracks running jobs
///
/// This is a separate structure to be able to borrow it mutably at the same
/// time as the connection to the database is borrowed
#[derive(Default)]
struct JobTracker {
    /// Stores a mapping from the job queue name to the job factory
    factories: HashMap<&'static str, JobFactory>,

    /// A join set of all the currently running jobs
    running_jobs: JoinSet<JobResult>,

    /// Stores a mapping from the Tokio task ID to the job context
    job_contexts: HashMap<tokio::task::Id, JobContext>,

    /// Stores the last `join_next_with_id` result for processing, in case we
    /// got woken up in `collect_next_job`
    last_join_result: Option<Result<(tokio::task::Id, JobResult), tokio::task::JoinError>>,
}

impl JobTracker {
    /// Returns the queue names that are currently being tracked
    fn queues(&self) -> Vec<&'static str> {
        self.factories.keys().copied().collect()
    }

    /// Spawn a job on the job tracker
    fn spawn_job(&mut self, state: State, context: JobContext, payload: JobPayload) {
        let factory = self.factories.get(context.queue_name.as_str()).cloned();
        let task = {
            let context = context.clone();
            let span = context.span();
            async move {
                // We should never crash, but in case we do, we do that in the task and
                // don't crash the worker
                let job = factory.expect("unknown job factory")(payload);
                tracing::info!("Running job");
                job.run(&state, context).await
            }
            .instrument(span)
        };

        let handle = self.running_jobs.spawn(task);
        self.job_contexts.insert(handle.id(), context);
    }

    /// Returns `true` if there are currently running jobs
    fn has_jobs(&self) -> bool {
        !self.running_jobs.is_empty()
    }

    /// Returns the number of currently running jobs
    ///
    /// This also includes the job result which may be stored for processing
    fn running_jobs(&self) -> usize {
        self.running_jobs.len() + usize::from(self.last_join_result.is_some())
    }

    async fn collect_next_job(&mut self) {
        // Double-check that we don't have a job result stored
        if self.last_join_result.is_some() {
            tracing::error!(
                "Job tracker already had a job result stored, this should never happen!"
            );
            return;
        }

        self.last_join_result = self.running_jobs.join_next_with_id().await;
    }

    /// Process all the jobs which are currently running
    ///
    /// If `blocking` is `true`, this function will block until all the jobs
    /// are finished. Otherwise, it will return as soon as it processed the
    /// already finished jobs.
    #[allow(clippy::too_many_lines)]
    async fn process_jobs<E: std::error::Error + Send + Sync + 'static>(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        repo: &mut dyn RepositoryAccess<Error = E>,
        blocking: bool,
    ) -> Result<(), E> {
        if self.last_join_result.is_none() {
            if blocking {
                self.last_join_result = self.running_jobs.join_next_with_id().await;
            } else {
                self.last_join_result = self.running_jobs.try_join_next_with_id();
            }
        }

        while let Some(result) = self.last_join_result.take() {
            // TODO: add metrics to track the job status and the time it took
            match result {
                // The job succeeded
                Ok((id, Ok(()))) => {
                    let context = self
                        .job_contexts
                        .remove(&id)
                        .expect("Job context not found");

                    tracing::info!(
                        job.id = %context.id,
                        job.queue_name = %context.queue_name,
                        job.attempt = %context.attempt,
                        "Job completed"
                    );

                    repo.queue_job()
                        .mark_as_completed(clock, context.id)
                        .await?;
                }

                // The job failed
                Ok((id, Err(e))) => {
                    let context = self
                        .job_contexts
                        .remove(&id)
                        .expect("Job context not found");

                    let reason = format!("{:?}", e.error);
                    repo.queue_job()
                        .mark_as_failed(clock, context.id, &reason)
                        .await?;

                    match e.decision {
                        JobErrorDecision::Fail => {
                            tracing::error!(
                                error = &e as &dyn std::error::Error,
                                job.id = %context.id,
                                job.queue_name = %context.queue_name,
                                job.attempt = %context.attempt,
                                "Job failed, not retrying"
                            );
                        }

                        JobErrorDecision::Retry => {
                            if context.attempt < MAX_ATTEMPTS {
                                tracing::warn!(
                                    error = &e as &dyn std::error::Error,
                                    job.id = %context.id,
                                    job.queue_name = %context.queue_name,
                                    job.attempt = %context.attempt,
                                    "Job failed, will retry"
                                );

                                // TODO: retry with an exponential backoff, once we know how to
                                // schedule jobs in the future
                                repo.queue_job().retry(&mut *rng, clock, context.id).await?;
                            } else {
                                tracing::error!(
                                    error = &e as &dyn std::error::Error,
                                    job.id = %context.id,
                                    job.queue_name = %context.queue_name,
                                    job.attempt = %context.attempt,
                                    "Job failed too many times, abandonning"
                                );
                            }
                        }
                    }
                }

                // The job crashed (or was aborted)
                Err(e) => {
                    let id = e.id();
                    let context = self
                        .job_contexts
                        .remove(&id)
                        .expect("Job context not found");

                    let reason = e.to_string();
                    repo.queue_job()
                        .mark_as_failed(clock, context.id, &reason)
                        .await?;

                    if context.attempt < MAX_ATTEMPTS {
                        tracing::warn!(
                            error = &e as &dyn std::error::Error,
                            job.id = %context.id,
                            job.queue_name = %context.queue_name,
                            job.attempt = %context.attempt,
                            "Job crashed, will retry"
                        );

                        repo.queue_job().retry(&mut *rng, clock, context.id).await?;
                    } else {
                        tracing::error!(
                            error = &e as &dyn std::error::Error,
                            job.id = %context.id,
                            job.queue_name = %context.queue_name,
                            job.attempt = %context.attempt,
                            "Job crashed too many times, abandonning"
                        );
                    }
                }
            };

            if blocking {
                self.last_join_result = self.running_jobs.join_next_with_id().await;
            } else {
                self.last_join_result = self.running_jobs.try_join_next_with_id();
            }
        }

        Ok(())
    }
}
