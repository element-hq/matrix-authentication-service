// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::ops::{Deref, DerefMut};

use async_trait::async_trait;
use futures_util::{FutureExt, TryFutureExt, future::BoxFuture};
use mas_storage::{
    BoxRepository, BoxRepositoryFactory, MapErr, Repository, RepositoryAccess, RepositoryError,
    RepositoryFactory, RepositoryTransaction,
    app_session::AppSessionRepository,
    compat::{
        CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository,
        CompatSsoLoginRepository,
    },
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository, OAuth2ClientRepository,
        OAuth2DeviceCodeGrantRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    personal::PersonalSessionRepository,
    policy_data::PolicyDataRepository,
    queue::{QueueJobRepository, QueueScheduleRepository, QueueWorkerRepository},
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthLinkTokenRepository,
        UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository,
    },
    user::{
        BrowserSessionRepository, UserEmailRepository, UserPasswordRepository,
        UserRecoveryRepository, UserRegistrationRepository, UserRegistrationTokenRepository,
        UserRepository, UserTermsRepository,
    },
};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use tracing::Instrument;

use crate::{
    DatabaseError,
    app_session::PgAppSessionRepository,
    compat::{
        PgCompatAccessTokenRepository, PgCompatRefreshTokenRepository, PgCompatSessionRepository,
        PgCompatSsoLoginRepository,
    },
    oauth2::{
        PgOAuth2AccessTokenRepository, PgOAuth2AuthorizationGrantRepository,
        PgOAuth2ClientRepository, PgOAuth2DeviceCodeGrantRepository,
        PgOAuth2RefreshTokenRepository, PgOAuth2SessionRepository,
    },
    personal::{PgPersonalAccessTokenRepository, PgPersonalSessionRepository},
    policy_data::PgPolicyDataRepository,
    queue::{
        job::PgQueueJobRepository, schedule::PgQueueScheduleRepository,
        worker::PgQueueWorkerRepository,
    },
    telemetry::DB_CLIENT_CONNECTIONS_CREATE_TIME_HISTOGRAM,
    upstream_oauth2::{
        PgUpstreamOAuthLinkRepository, PgUpstreamOAuthLinkTokenRepository,
        PgUpstreamOAuthProviderRepository, PgUpstreamOAuthSessionRepository,
    },
    user::{
        PgBrowserSessionRepository, PgUserEmailRepository, PgUserPasswordRepository,
        PgUserRecoveryRepository, PgUserRegistrationRepository, PgUserRegistrationTokenRepository,
        PgUserRepository, PgUserTermsRepository,
    },
};

/// An implementation of the [`RepositoryFactory`] trait backed by a PostgreSQL
/// connection pool.
#[derive(Clone)]
pub struct PgRepositoryFactory {
    pool: PgPool,
}

impl PgRepositoryFactory {
    /// Create a new [`PgRepositoryFactory`] from a PostgreSQL connection pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Box the factory
    #[must_use]
    pub fn boxed(self) -> BoxRepositoryFactory {
        Box::new(self)
    }

    /// Get the underlying PostgreSQL connection pool
    #[must_use]
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }
}

#[async_trait]
impl RepositoryFactory for PgRepositoryFactory {
    async fn create(&self) -> Result<BoxRepository, RepositoryError> {
        let start = std::time::Instant::now();
        let repo = PgRepository::from_pool(&self.pool)
            .await
            .map_err(RepositoryError::from_error)?
            .boxed();

        // Measure the time it took to create the connection
        let duration = start.elapsed();
        let duration_ms = duration.as_millis().try_into().unwrap_or(u64::MAX);
        DB_CLIENT_CONNECTIONS_CREATE_TIME_HISTOGRAM.record(duration_ms, &[]);

        Ok(repo)
    }
}

/// An implementation of the [`Repository`] trait backed by a PostgreSQL
/// transaction.
pub struct PgRepository<C = Transaction<'static, Postgres>> {
    conn: C,
}

impl PgRepository {
    /// Create a new [`PgRepository`] from a PostgreSQL connection pool,
    /// starting a transaction.
    ///
    /// # Errors
    ///
    /// Returns a [`DatabaseError`] if the transaction could not be started.
    pub async fn from_pool(pool: &PgPool) -> Result<Self, DatabaseError> {
        let txn = pool.begin().await?;
        Ok(Self::from_conn(txn))
    }

    /// Transform the repository into a type-erased [`BoxRepository`]
    pub fn boxed(self) -> BoxRepository {
        Box::new(MapErr::new(self, RepositoryError::from_error))
    }
}

impl<C> PgRepository<C> {
    /// Create a new [`PgRepository`] from an existing PostgreSQL connection
    /// with a transaction
    pub fn from_conn(conn: C) -> Self {
        PgRepository { conn }
    }

    /// Consume this [`PgRepository`], returning the underlying connection.
    pub fn into_inner(self) -> C {
        self.conn
    }
}

impl<C> AsRef<C> for PgRepository<C> {
    fn as_ref(&self) -> &C {
        &self.conn
    }
}

impl<C> AsMut<C> for PgRepository<C> {
    fn as_mut(&mut self) -> &mut C {
        &mut self.conn
    }
}

impl<C> Deref for PgRepository<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl<C> DerefMut for PgRepository<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl Repository<DatabaseError> for PgRepository {}

impl RepositoryTransaction for PgRepository {
    type Error = DatabaseError;

    fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        let span = tracing::info_span!("db.save");
        self.conn
            .commit()
            .map_err(DatabaseError::from)
            .instrument(span)
            .boxed()
    }

    fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
        let span = tracing::info_span!("db.cancel");
        self.conn
            .rollback()
            .map_err(DatabaseError::from)
            .instrument(span)
            .boxed()
    }
}

impl<C> RepositoryAccess for PgRepository<C>
where
    C: AsMut<PgConnection> + Send,
{
    type Error = DatabaseError;

    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthLinkRepository::new(self.conn.as_mut()))
    }

    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthProviderRepository::new(self.conn.as_mut()))
    }

    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthSessionRepository::new(self.conn.as_mut()))
    }

    fn upstream_oauth_link_token<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgUpstreamOAuthLinkTokenRepository::new(self.conn.as_mut()))
    }

    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRepository::new(self.conn.as_mut()))
    }

    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserEmailRepository::new(self.conn.as_mut()))
    }

    fn user_password<'c>(
        &'c mut self,
    ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserPasswordRepository::new(self.conn.as_mut()))
    }

    fn user_recovery<'c>(
        &'c mut self,
    ) -> Box<dyn UserRecoveryRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRecoveryRepository::new(self.conn.as_mut()))
    }

    fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserTermsRepository::new(self.conn.as_mut()))
    }

    fn user_registration<'c>(
        &'c mut self,
    ) -> Box<dyn UserRegistrationRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRegistrationRepository::new(self.conn.as_mut()))
    }

    fn user_registration_token<'c>(
        &'c mut self,
    ) -> Box<dyn UserRegistrationTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRegistrationTokenRepository::new(self.conn.as_mut()))
    }

    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgBrowserSessionRepository::new(self.conn.as_mut()))
    }

    fn app_session<'c>(&'c mut self) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgAppSessionRepository::new(self.conn.as_mut()))
    }

    fn oauth2_client<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2ClientRepository::new(self.conn.as_mut()))
    }

    fn oauth2_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2AuthorizationGrantRepository::new(
            self.conn.as_mut(),
        ))
    }

    fn oauth2_session<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2SessionRepository::new(self.conn.as_mut()))
    }

    fn oauth2_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2AccessTokenRepository::new(self.conn.as_mut()))
    }

    fn oauth2_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2RefreshTokenRepository::new(self.conn.as_mut()))
    }

    fn oauth2_device_code_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2DeviceCodeGrantRepository<Error = Self::Error> + 'c> {
        Box::new(PgOAuth2DeviceCodeGrantRepository::new(self.conn.as_mut()))
    }

    fn compat_session<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgCompatSessionRepository::new(self.conn.as_mut()))
    }

    fn compat_sso_login<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSsoLoginRepository<Error = Self::Error> + 'c> {
        Box::new(PgCompatSsoLoginRepository::new(self.conn.as_mut()))
    }

    fn compat_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatAccessTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgCompatAccessTokenRepository::new(self.conn.as_mut()))
    }

    fn compat_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatRefreshTokenRepository<Error = Self::Error> + 'c> {
        Box::new(PgCompatRefreshTokenRepository::new(self.conn.as_mut()))
    }

    fn personal_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn mas_storage::personal::PersonalAccessTokenRepository<Error = Self::Error> + 'c>
    {
        Box::new(PgPersonalAccessTokenRepository::new(self.conn.as_mut()))
    }

    fn personal_session<'c>(
        &'c mut self,
    ) -> Box<dyn PersonalSessionRepository<Error = Self::Error> + 'c> {
        Box::new(PgPersonalSessionRepository::new(self.conn.as_mut()))
    }

    fn queue_worker<'c>(&'c mut self) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueWorkerRepository::new(self.conn.as_mut()))
    }

    fn queue_job<'c>(&'c mut self) -> Box<dyn QueueJobRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueJobRepository::new(self.conn.as_mut()))
    }

    fn queue_schedule<'c>(
        &'c mut self,
    ) -> Box<dyn QueueScheduleRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueScheduleRepository::new(self.conn.as_mut()))
    }

    fn policy_data<'c>(&'c mut self) -> Box<dyn PolicyDataRepository<Error = Self::Error> + 'c> {
        Box::new(PgPolicyDataRepository::new(self.conn.as_mut()))
    }
}
