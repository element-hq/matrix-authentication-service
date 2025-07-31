// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Wrappers and useful type aliases

/// A wrapper which is used to map the error type of a repository to another
pub struct MapErr<R, F> {
    pub(crate) inner: R,
    pub(crate) mapper: F,
    _private: (),
}

impl<R, F> MapErr<R, F> {
    /// Create a new [`MapErr`] wrapper from an inner repository and a mapper
    /// function
    #[must_use]
    pub fn new(inner: R, mapper: F) -> Self {
        Self {
            inner,
            mapper,
            _private: (),
        }
    }
}

/// A macro to implement a repository trait for the [`MapErr`] wrapper and for
/// [`Box<R>`]
#[macro_export]
macro_rules! repository_impl {
    ($repo_trait:ident:
        $(
            async fn $method:ident (
                &mut self
                $(, $arg:ident: $arg_ty:ty )*
                $(,)?
            ) -> Result<$ret_ty:ty, Self::Error>;
        )*
    ) => {
        #[::async_trait::async_trait]
        impl<R: ?Sized> $repo_trait for ::std::boxed::Box<R>
        where
            R: $repo_trait,
        {
            type Error = <R as $repo_trait>::Error;

            $(
                async fn $method (&mut self $(, $arg: $arg_ty)*) -> Result<$ret_ty, Self::Error> {
                    (**self).$method ( $($arg),* ).await
                }
            )*
        }

        #[::async_trait::async_trait]
        impl<R, F, E> $repo_trait for $crate::MapErr<R, F>
        where
            R: $repo_trait,
            F: FnMut(<R as $repo_trait>::Error) -> E + ::std::marker::Send + ::std::marker::Sync,
        {
            type Error = E;

            $(
                async fn $method (&mut self $(, $arg: $arg_ty)*) -> Result<$ret_ty, Self::Error> {
                    self.inner.$method ( $($arg),* ).await.map_err(&mut self.mapper)
                }
            )*
        }
    };
}
