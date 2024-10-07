// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use futures_util::future::BoxFuture;
use thiserror::Error;

use crate::{
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
    queue::QueueWorkerRepository,
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    },
    user::{
        BrowserSessionRepository, UserEmailRepository, UserPasswordRepository,
        UserRecoveryRepository, UserRepository, UserTermsRepository,
    },
};

/// A [`Repository`] helps interacting with the underlying storage backend.
pub trait Repository<E>:
    RepositoryAccess<Error = E> + RepositoryTransaction<Error = E> + Send
where
    E: std::error::Error + Send + Sync + 'static,
{
}

/// An opaque, type-erased error
#[derive(Debug, Error)]
#[error(transparent)]
pub struct RepositoryError {
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl RepositoryError {
    /// Construct a [`RepositoryError`] from any error kind
    pub fn from_error<E>(value: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(value),
        }
    }
}

/// A type-erased [`Repository`]
pub type BoxRepository = Box<dyn Repository<RepositoryError> + Send + Sync + 'static>;

/// A [`RepositoryTransaction`] can be saved or cancelled, after a series
/// of operations.
pub trait RepositoryTransaction {
    /// The error type used by the [`Self::save`] and [`Self::cancel`] functions
    type Error;

    /// Commit the transaction
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage backend failed to commit the
    /// transaction.
    fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>>;

    /// Rollback the transaction
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage backend failed to rollback
    /// the transaction.
    fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>>;
}

/// Access the various repositories the backend implements.
///
/// All the methods return a boxed trait object, which can be used to access a
/// particular repository. The lifetime of the returned object is bound to the
/// lifetime of the whole repository, so that only one mutable reference to the
/// repository is used at a time.
///
/// When adding a new repository, you should add a new method to this trait, and
/// update the implementations for [`crate::MapErr`] and [`Box<R>`] below.
///
/// Note: this used to have generic associated types to avoid boxing all the
/// repository traits, but that was removed because it made almost impossible to
/// box the trait object. This might be a shortcoming of the initial
/// implementation of generic associated types, and might be fixed in the
/// future.
pub trait RepositoryAccess: Send {
    /// The backend-specific error type used by each repository.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get an [`UpstreamOAuthLinkRepository`]
    fn upstream_oauth_link<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c>;

    /// Get an [`UpstreamOAuthProviderRepository`]
    fn upstream_oauth_provider<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c>;

    /// Get an [`UpstreamOAuthSessionRepository`]
    fn upstream_oauth_session<'c>(
        &'c mut self,
    ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserRepository`]
    fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserEmailRepository`]
    fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserPasswordRepository`]
    fn user_password<'c>(&'c mut self)
        -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserRecoveryRepository`]
    fn user_recovery<'c>(&'c mut self)
        -> Box<dyn UserRecoveryRepository<Error = Self::Error> + 'c>;

    /// Get an [`UserTermsRepository`]
    fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c>;

    /// Get a [`BrowserSessionRepository`]
    fn browser_session<'c>(
        &'c mut self,
    ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c>;

    /// Get a [`AppSessionRepository`]
    fn app_session<'c>(&'c mut self) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuth2ClientRepository`]
    fn oauth2_client<'c>(&'c mut self)
        -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuth2AuthorizationGrantRepository`]
    fn oauth2_authorization_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuth2SessionRepository`]
    fn oauth2_session<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuth2AccessTokenRepository`]
    fn oauth2_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuth2RefreshTokenRepository`]
    fn oauth2_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c>;

    /// Get an [`OAuth2DeviceCodeGrantRepository`]
    fn oauth2_device_code_grant<'c>(
        &'c mut self,
    ) -> Box<dyn OAuth2DeviceCodeGrantRepository<Error = Self::Error> + 'c>;

    /// Get a [`CompatSessionRepository`]
    fn compat_session<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSessionRepository<Error = Self::Error> + 'c>;

    /// Get a [`CompatSsoLoginRepository`]
    fn compat_sso_login<'c>(
        &'c mut self,
    ) -> Box<dyn CompatSsoLoginRepository<Error = Self::Error> + 'c>;

    /// Get a [`CompatAccessTokenRepository`]
    fn compat_access_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatAccessTokenRepository<Error = Self::Error> + 'c>;

    /// Get a [`CompatRefreshTokenRepository`]
    fn compat_refresh_token<'c>(
        &'c mut self,
    ) -> Box<dyn CompatRefreshTokenRepository<Error = Self::Error> + 'c>;

    /// Get a [`JobRepository`]
    fn job<'c>(&'c mut self) -> Box<dyn JobRepository<Error = Self::Error> + 'c>;

    /// Get a [`QueueWorkerRepository`]
    fn queue_worker<'c>(&'c mut self) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c>;
}

/// Implementations of the [`RepositoryAccess`], [`RepositoryTransaction`] and
/// [`Repository`] for the [`crate::MapErr`] wrapper and [`Box<R>`]
mod impls {
    use futures_util::{future::BoxFuture, FutureExt, TryFutureExt};

    use super::RepositoryAccess;
    use crate::{
        app_session::AppSessionRepository,
        compat::{
            CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository,
            CompatSsoLoginRepository,
        },
        job::JobRepository,
        oauth2::{
            OAuth2AccessTokenRepository, OAuth2AuthorizationGrantRepository,
            OAuth2ClientRepository, OAuth2DeviceCodeGrantRepository, OAuth2RefreshTokenRepository,
            OAuth2SessionRepository,
        },
        queue::QueueWorkerRepository,
        upstream_oauth2::{
            UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
            UpstreamOAuthSessionRepository,
        },
        user::{
            BrowserSessionRepository, UserEmailRepository, UserPasswordRepository, UserRepository,
            UserTermsRepository,
        },
        MapErr, Repository, RepositoryTransaction,
    };

    // --- Repository ---
    impl<R, F, E1, E2> Repository<E2> for MapErr<R, F>
    where
        R: Repository<E1> + RepositoryAccess<Error = E1> + RepositoryTransaction<Error = E1>,
        F: FnMut(E1) -> E2 + Send + Sync + 'static,
        E1: std::error::Error + Send + Sync + 'static,
        E2: std::error::Error + Send + Sync + 'static,
    {
    }

    // --- RepositoryTransaction --
    impl<R, F, E> RepositoryTransaction for MapErr<R, F>
    where
        R: RepositoryTransaction,
        R::Error: 'static,
        F: FnMut(R::Error) -> E + Send + Sync + 'static,
        E: std::error::Error,
    {
        type Error = E;

        fn save(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
            Box::new(self.inner).save().map_err(self.mapper).boxed()
        }

        fn cancel(self: Box<Self>) -> BoxFuture<'static, Result<(), Self::Error>> {
            Box::new(self.inner).cancel().map_err(self.mapper).boxed()
        }
    }

    // --- RepositoryAccess --
    impl<R, F, E> RepositoryAccess for MapErr<R, F>
    where
        R: RepositoryAccess,
        R::Error: 'static,
        F: FnMut(R::Error) -> E + Send + Sync + 'static,
        E: std::error::Error + Send + Sync + 'static,
    {
        type Error = E;

        fn upstream_oauth_link<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.upstream_oauth_link(),
                &mut self.mapper,
            ))
        }

        fn upstream_oauth_provider<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.upstream_oauth_provider(),
                &mut self.mapper,
            ))
        }

        fn upstream_oauth_session<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.upstream_oauth_session(),
                &mut self.mapper,
            ))
        }

        fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user(), &mut self.mapper))
        }

        fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_email(), &mut self.mapper))
        }

        fn user_password<'c>(
            &'c mut self,
        ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_password(), &mut self.mapper))
        }

        fn user_recovery<'c>(
            &'c mut self,
        ) -> Box<dyn crate::user::UserRecoveryRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_recovery(), &mut self.mapper))
        }

        fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.user_terms(), &mut self.mapper))
        }

        fn browser_session<'c>(
            &'c mut self,
        ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.browser_session(), &mut self.mapper))
        }

        fn app_session<'c>(
            &'c mut self,
        ) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.app_session(), &mut self.mapper))
        }

        fn oauth2_client<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.oauth2_client(), &mut self.mapper))
        }

        fn oauth2_authorization_grant<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth2_authorization_grant(),
                &mut self.mapper,
            ))
        }

        fn oauth2_session<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.oauth2_session(), &mut self.mapper))
        }

        fn oauth2_access_token<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth2_access_token(),
                &mut self.mapper,
            ))
        }

        fn oauth2_refresh_token<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth2_refresh_token(),
                &mut self.mapper,
            ))
        }

        fn oauth2_device_code_grant<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2DeviceCodeGrantRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.oauth2_device_code_grant(),
                &mut self.mapper,
            ))
        }

        fn compat_session<'c>(
            &'c mut self,
        ) -> Box<dyn CompatSessionRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.compat_session(), &mut self.mapper))
        }

        fn compat_sso_login<'c>(
            &'c mut self,
        ) -> Box<dyn CompatSsoLoginRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.compat_sso_login(), &mut self.mapper))
        }

        fn compat_access_token<'c>(
            &'c mut self,
        ) -> Box<dyn CompatAccessTokenRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.compat_access_token(),
                &mut self.mapper,
            ))
        }

        fn compat_refresh_token<'c>(
            &'c mut self,
        ) -> Box<dyn CompatRefreshTokenRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(
                self.inner.compat_refresh_token(),
                &mut self.mapper,
            ))
        }

        fn job<'c>(&'c mut self) -> Box<dyn JobRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.job(), &mut self.mapper))
        }

        fn queue_worker<'c>(
            &'c mut self,
        ) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c> {
            Box::new(MapErr::new(self.inner.queue_worker(), &mut self.mapper))
        }
    }

    impl<R: RepositoryAccess + ?Sized> RepositoryAccess for Box<R> {
        type Error = R::Error;

        fn upstream_oauth_link<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthLinkRepository<Error = Self::Error> + 'c> {
            (**self).upstream_oauth_link()
        }

        fn upstream_oauth_provider<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthProviderRepository<Error = Self::Error> + 'c> {
            (**self).upstream_oauth_provider()
        }

        fn upstream_oauth_session<'c>(
            &'c mut self,
        ) -> Box<dyn UpstreamOAuthSessionRepository<Error = Self::Error> + 'c> {
            (**self).upstream_oauth_session()
        }

        fn user<'c>(&'c mut self) -> Box<dyn UserRepository<Error = Self::Error> + 'c> {
            (**self).user()
        }

        fn user_email<'c>(&'c mut self) -> Box<dyn UserEmailRepository<Error = Self::Error> + 'c> {
            (**self).user_email()
        }

        fn user_password<'c>(
            &'c mut self,
        ) -> Box<dyn UserPasswordRepository<Error = Self::Error> + 'c> {
            (**self).user_password()
        }

        fn user_recovery<'c>(
            &'c mut self,
        ) -> Box<dyn crate::user::UserRecoveryRepository<Error = Self::Error> + 'c> {
            (**self).user_recovery()
        }

        fn user_terms<'c>(&'c mut self) -> Box<dyn UserTermsRepository<Error = Self::Error> + 'c> {
            (**self).user_terms()
        }

        fn browser_session<'c>(
            &'c mut self,
        ) -> Box<dyn BrowserSessionRepository<Error = Self::Error> + 'c> {
            (**self).browser_session()
        }

        fn app_session<'c>(
            &'c mut self,
        ) -> Box<dyn AppSessionRepository<Error = Self::Error> + 'c> {
            (**self).app_session()
        }

        fn oauth2_client<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2ClientRepository<Error = Self::Error> + 'c> {
            (**self).oauth2_client()
        }

        fn oauth2_authorization_grant<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2AuthorizationGrantRepository<Error = Self::Error> + 'c> {
            (**self).oauth2_authorization_grant()
        }

        fn oauth2_session<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2SessionRepository<Error = Self::Error> + 'c> {
            (**self).oauth2_session()
        }

        fn oauth2_access_token<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2AccessTokenRepository<Error = Self::Error> + 'c> {
            (**self).oauth2_access_token()
        }

        fn oauth2_refresh_token<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2RefreshTokenRepository<Error = Self::Error> + 'c> {
            (**self).oauth2_refresh_token()
        }

        fn oauth2_device_code_grant<'c>(
            &'c mut self,
        ) -> Box<dyn OAuth2DeviceCodeGrantRepository<Error = Self::Error> + 'c> {
            (**self).oauth2_device_code_grant()
        }

        fn compat_session<'c>(
            &'c mut self,
        ) -> Box<dyn CompatSessionRepository<Error = Self::Error> + 'c> {
            (**self).compat_session()
        }

        fn compat_sso_login<'c>(
            &'c mut self,
        ) -> Box<dyn CompatSsoLoginRepository<Error = Self::Error> + 'c> {
            (**self).compat_sso_login()
        }

        fn compat_access_token<'c>(
            &'c mut self,
        ) -> Box<dyn CompatAccessTokenRepository<Error = Self::Error> + 'c> {
            (**self).compat_access_token()
        }

        fn compat_refresh_token<'c>(
            &'c mut self,
        ) -> Box<dyn CompatRefreshTokenRepository<Error = Self::Error> + 'c> {
            (**self).compat_refresh_token()
        }

        fn job<'c>(&'c mut self) -> Box<dyn JobRepository<Error = Self::Error> + 'c> {
            (**self).job()
        }

        fn queue_worker<'c>(
            &'c mut self,
        ) -> Box<dyn QueueWorkerRepository<Error = Self::Error> + 'c> {
            (**self).queue_worker()
        }
    }
}
