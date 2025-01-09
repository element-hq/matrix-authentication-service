// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context;
use axum::{
    extract::{Form, Path, Query, State},
    response::{Html, IntoResponse, Response},
};
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_router::UrlBuilder;
use mas_storage::{
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    user::UserEmailRepository,
    BoxClock, BoxRepository, BoxRng, RepositoryAccess,
};
use mas_templates::{EmailVerificationPageContext, TemplateContext, Templates};
use serde::Deserialize;
use ulid::Ulid;

use crate::{views::shared::OptionalPostAuthAction, BoundActivityTracker, PreferredLanguage};

#[expect(dead_code)]
#[derive(Deserialize, Debug)]
pub struct CodeForm {
    code: String,
}

#[tracing::instrument(
    name = "handlers.views.account_email_verify.get",
    fields(user_email.id = %id),
    skip_all,
    err,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    Query(_query): Query<OptionalPostAuthAction>,
    Path(id): Path<Ulid>,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let user_email = repo
        .user_email()
        .lookup(id)
        .await?
        .filter(|u| u.user_id == session.user.id)
        .context("Could not find user email")?;

    let ctx = EmailVerificationPageContext::new(user_email)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_account_verify_email(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(
    name = "handlers.views.account_email_verify.post",
    fields(user_email.id = %id),
    skip_all,
    err,
)]
pub(crate) async fn post(
    clock: BoxClock,
    mut rng: BoxRng,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    Path(id): Path<Ulid>,
    Form(form): Form<ProtectedForm<CodeForm>>,
) -> Result<Response, FancyError> {
    let _form = cookie_jar.verify_form(&clock, form)?;
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let Some(session) = maybe_session else {
        let login = mas_router::Login::default();
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    let _user_email = repo
        .user_email()
        .lookup(id)
        .await?
        .filter(|u| u.user_id == session.user.id)
        .context("Could not find user email")?;

    // XXX: this logic should be extracted somewhere else, since most of it is
    // duplicated in mas_graphql

    // TODO: Use the new email authentication codes

    repo.queue_job()
        .schedule_job(&mut rng, &clock, ProvisionUserJob::new(&session.user))
        .await?;

    repo.save().await?;

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let destination = query.go_next_or_default(&url_builder, &mas_router::Account::default());
    Ok((cookie_jar, destination).into_response())
}
