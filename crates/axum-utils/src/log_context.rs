// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Ergonomic glue between domain types and the [`LogContext`] requester slot.
//!
//! Auth-resolution sites can call `value.maybe_record_as_requester()` on a
//! [`User`], [`BrowserSession`], [`Session`], [`CompatSession`] or [`Client`]
//! instead of reaching for [`LogContext::maybe_set_requester`] + [`Requester`]
//! directly. Each call site should record the entity that *authenticated the
//! request* exactly once; [`LogContext`] is first-writer-wins, so an accidental
//! second call is harmless.

use mas_context::{LogContext, Requester};
use mas_data_model::{BrowserSession, Client, CompatSession, Session, User};

pub trait RecordAsRequester {
    /// Record `self` as the [`Requester`] on the current [`LogContext`], if
    /// any.
    ///
    /// First writer wins — calling on a request that already has a requester
    /// recorded is a no-op.
    fn maybe_record_as_requester(&self);
}

impl RecordAsRequester for User {
    fn maybe_record_as_requester(&self) {
        LogContext::maybe_set_requester(Requester::user(self.id, self.username.clone()));
    }
}

impl RecordAsRequester for BrowserSession {
    fn maybe_record_as_requester(&self) {
        self.user.maybe_record_as_requester();
    }
}

impl RecordAsRequester for Session {
    /// Records the `OAuth2` session's user (without a username) when it has
    /// one, otherwise the client acting on its own behalf
    /// (client-credentials).
    fn maybe_record_as_requester(&self) {
        if let Some(user_id) = self.user_id {
            LogContext::maybe_set_requester(Requester::user_id_only(user_id));
        } else {
            LogContext::maybe_set_requester(Requester::oauth2_client(self.client_id));
        }
    }
}

impl RecordAsRequester for CompatSession {
    fn maybe_record_as_requester(&self) {
        LogContext::maybe_set_requester(Requester::user_id_only(self.user_id));
    }
}

impl RecordAsRequester for Client {
    fn maybe_record_as_requester(&self) {
        LogContext::maybe_set_requester(Requester::oauth2_client(self.id));
    }
}
