// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::ops::{Deref, DerefMut};

use futures_util::{future::BoxFuture, FutureExt, TryFutureExt};
use mas_storage::{
    app_session::AppSessionRepository,
    compat::{
        CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository,
        CompatSsoLoginRepository,
    },
    job::JobRepository,
    oauth2::{
        OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository, OAuth2ClientRepository,
        OAuth2DeviceCodeGrantRepository, OAuth2RefreshTokenRepository, OAuth2SessionRepository,
    },
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    },
    user::{BrowserSessionRepository, UserEmailRepository, UserPasswordRepository, UserRepository},
    BoxRepository, MapErr, Repository, RepositoryAccess, RepositoryError, RepositoryTransaction,
};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use tracing::Instrument;

use crate::{
    app_session::PgAppSessionRepository,
    compat::{
        PgCompatAccessTokenRepository, PgCompatRefreshTokenRepository, PgCompatSessionRepository,
        PgCompatSsoLoginRepository,
    },
    job::PgJobRepository,
    oauth2::{
        PgOAuth2AccessTokenRepository, PgOAuth2AuthorizationGrantRepository,
        PgOAuth2ClientRepository, PgOAuth2DeviceCodeGrantRepository,
        PgOAuth2RefreshTokenRepository, PgOAuth2SessionRepository,
    },
    queue::worker::PgQueueWorkerRepository,
    upstream_oauth2::{
        PgUpstreamOAuthLinkRepository, PgUpstreamOAuthProviderRepository,
        PgUpstreamOAuthSessionRepository,
    },
    user::{
        PgBrowserSessionRepository, PgUserEmailRepository, PgUserPasswordRepository,
        PgUserRecoveryRepository, PgUserRepository, PgUserTermsRepository,
    },
    DatabaseError,
};

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
    ) -> Box<dyn mas_storage::user::UserRecoveryRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserRecoveryRepository::new(self.conn.as_mut()))
    }

    fn user_terms<'c>(
        &'c mut self,
    ) -> Box<dyn mas_storage::user::UserTermsRepository<Error = Self::Error> + 'c> {
        Box::new(PgUserTermsRepository::new(self.conn.as_mut()))
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

    fn job<'c>(&'c mut self) -> Box<dyn JobRepository<Error = Self::Error> + 'c> {
        Box::new(PgJobRepository::new(self.conn.as_mut()))
    }

    fn queue_worker<'c>(
        &'c mut self,
    ) -> Box<dyn mas_storage::queue::QueueWorkerRepository<Error = Self::Error> + 'c> {
        Box::new(PgQueueWorkerRepository::new(self.conn.as_mut()))
    }
}
