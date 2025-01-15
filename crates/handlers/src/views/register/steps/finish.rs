// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context as _;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use axum_extra::TypedHeader;
use mas_axum_utils::{cookies::CookieJar, FancyError, SessionInfoExt as _};
use mas_data_model::UserAgent;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    user::UserEmailFilter,
    BoxClock, BoxRepository, BoxRng,
};
use ulid::Ulid;

use crate::{views::shared::OptionalPostAuthAction, BoundActivityTracker};

#[tracing::instrument(
    name = "handlers.views.register.steps.finish.get",
    fields(user_registration.id = %id),
    skip_all,
    err,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    State(url_builder): State<UrlBuilder>,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
) -> Result<impl IntoResponse, FancyError> {
    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("User registration not found")?;

    // If the registration is completed, we can go to the registration destination
    // XXX: this might not be the right thing to do? Maybe an error page would be
    // better?
    if registration.completed_at.is_some() {
        let post_auth_action: Option<PostAuthAction> = registration
            .post_auth_action
            .map(serde_json::from_value)
            .transpose()?;

        return Ok((
            cookie_jar,
            OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder),
        ));
    }

    // Let's perform last minute checks on the registration, especially to avoid
    // race conditions where multiple users register with the same username or email
    // address

    if repo.user().exists(&registration.username).await? {
        return Err(FancyError::from(anyhow::anyhow!(
            "Username is already taken"
        )));
    }

    // TODO: query the homeserver

    // For now, we require an email address on the registration, but this might
    // change in the future
    let email_authentication_id = registration
        .email_authentication_id
        .context("No email authentication started for this registration")?;
    let email_authentication = repo
        .user_email()
        .lookup_authentication(email_authentication_id)
        .await?
        .context("Could not load the email authentication")?;

    // Check that the email authentication has been completed
    if email_authentication.completed_at.is_none() {
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::RegisterVerifyEmail::new(id)),
        ));
    }

    // Check that the email address isn't already used
    if repo
        .user_email()
        .count(UserEmailFilter::new().for_email(&email_authentication.email))
        .await?
        > 0
    {
        return Err(FancyError::from(anyhow::anyhow!(
            "Email address is already used"
        )));
    }

    // Check that the display name is set
    if registration.display_name.is_none() {
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::RegisterDisplayName::new(registration.id)),
        ));
    }

    // Everuthing is good, let's complete the registration
    let registration = repo
        .user_registration()
        .complete(&clock, registration)
        .await?;

    // Now we can start the user creation
    let user = repo
        .user()
        .add(&mut rng, &clock, registration.username)
        .await?;
    // Also create a browser session which will log the user in
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, user_agent)
        .await?;

    repo.user_email()
        .add(&mut rng, &clock, &user, email_authentication.email)
        .await?;

    if let Some(password) = registration.password {
        let user_password = repo
            .user_password()
            .add(
                &mut rng,
                &clock,
                &user,
                password.version,
                password.hashed_password,
                None,
            )
            .await?;

        repo.browser_session()
            .authenticate_with_password(&mut rng, &clock, &user_session, &user_password)
            .await?;
    }

    if let Some(terms_url) = registration.terms_url {
        repo.user_terms()
            .accept_terms(&mut rng, &clock, &user, terms_url)
            .await?;
    }

    let mut job = ProvisionUserJob::new(&user);
    if let Some(display_name) = registration.display_name {
        job = job.set_display_name(display_name);
    }
    repo.queue_job().schedule_job(&mut rng, &clock, job).await?;

    repo.save().await?;

    activity_tracker
        .record_browser_session(&clock, &user_session)
        .await;

    let post_auth_action: Option<PostAuthAction> = registration
        .post_auth_action
        .map(serde_json::from_value)
        .transpose()?;

    // Login the user with the session we just created
    let cookie_jar = cookie_jar.set_session(&user_session);

    return Ok((
        cookie_jar,
        OptionalPostAuthAction::from(post_auth_action).go_next(&url_builder),
    ));
}
