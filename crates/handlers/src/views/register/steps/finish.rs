// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::{Arc, LazyLock};

use anyhow::Context as _;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::TypedHeader;
use chrono::Duration;
use mas_axum_utils::{InternalError, SessionInfoExt as _, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng, SiteConfig};
use mas_matrix::HomeserverConnection;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    queue::{ProvisionUserJob, QueueJobRepositoryExt as _},
    user::UserEmailFilter,
};
use mas_templates::{RegisterStepsEmailInUseContext, TemplateContext as _, Templates};
use opentelemetry::metrics::Counter;
use ulid::Ulid;

use super::super::cookie::UserRegistrationSessions;
use crate::{
    BoundActivityTracker, METER, PreferredLanguage, views::shared::OptionalPostAuthAction,
};

static PASSWORD_REGISTER_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.user.password_registration")
        .with_description("Number of password registrations")
        .with_unit("{registration}")
        .build()
});

#[tracing::instrument(
    name = "handlers.views.register.steps.finish.get",
    fields(user_registration.id = %id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    State(url_builder): State<UrlBuilder>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    State(templates): State<Templates>,
    State(site_config): State<SiteConfig>,
    PreferredLanguage(lang): PreferredLanguage,
    cookie_jar: CookieJar,
    Path(id): Path<Ulid>,
) -> Result<Response, InternalError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    let registration = repo
        .user_registration()
        .lookup(id)
        .await?
        .context("User registration not found")
        .map_err(InternalError::from_anyhow)?;

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
        )
            .into_response());
    }

    // Make sure the registration session hasn't expired
    // XXX: this duration is hard-coded, could be configurable
    if clock.now() - registration.created_at > Duration::hours(1) {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Registration session has expired"
        )));
    }

    // Check that this registration belongs to this browser
    let registrations = UserRegistrationSessions::load(&cookie_jar);
    if !registrations.contains(&registration) {
        // XXX: we should have a better error screen here
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Could not find the registration in the browser cookies"
        )));
    }

    // Let's perform last minute checks on the registration, especially to avoid
    // race conditions where multiple users register with the same username or email
    // address

    if repo.user().exists(&registration.username).await? {
        // XXX: this could have a better error message, but as this is unlikely to
        // happen, we're fine with a vague message for now
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Username is already taken"
        )));
    }

    if !homeserver
        .is_localpart_available(&registration.username)
        .await
        .map_err(InternalError::from_anyhow)?
    {
        return Err(InternalError::from_anyhow(anyhow::anyhow!(
            "Username is not available"
        )));
    }

    // Check if the registration token is required and was provided
    let registration_token = if site_config.registration_token_required {
        if let Some(registration_token_id) = registration.user_registration_token_id {
            let registration_token = repo
                .user_registration_token()
                .lookup(registration_token_id)
                .await?
                .context("Could not load the registration token")
                .map_err(InternalError::from_anyhow)?;

            if !registration_token.is_valid(clock.now()) {
                // XXX: the registration token isn't valid anymore, we should
                // have a better error in this case?
                return Err(InternalError::from_anyhow(anyhow::anyhow!(
                    "Registration token used is no longer valid"
                )));
            }

            Some(registration_token)
        } else {
            // Else redirect to the registration token page
            return Ok((
                cookie_jar,
                url_builder.redirect(&mas_router::RegisterToken::new(registration.id)),
            )
                .into_response());
        }
    } else {
        None
    };

    // If there is an email authentication, we need to check that the email
    // address was verified. If there is no email authentication attached, we
    // need to make sure the server doesn't require it
    let email_authentication =
        if let Some(email_authentication_id) = registration.email_authentication_id {
            let email_authentication = repo
                .user_email()
                .lookup_authentication(email_authentication_id)
                .await?
                .context("Could not load the email authentication")
                .map_err(InternalError::from_anyhow)?;

            // Check that the email authentication has been completed
            if email_authentication.completed_at.is_none() {
                return Ok((
                    cookie_jar,
                    url_builder.redirect(&mas_router::RegisterVerifyEmail::new(id)),
                )
                    .into_response());
            }

            // Check that the email address isn't already used
            // It is important to do that here, as we we're not checking during the
            // registration, because we don't want to disclose whether an email is
            // already being used or not before we verified it
            if repo
                .user_email()
                .count(UserEmailFilter::new().for_email(&email_authentication.email))
                .await?
                > 0
            {
                let action = registration
                    .post_auth_action
                    .map(serde_json::from_value)
                    .transpose()?;

                let ctx = RegisterStepsEmailInUseContext::new(email_authentication.email, action)
                    .with_language(lang);

                return Ok((
                    cookie_jar,
                    Html(templates.render_register_steps_email_in_use(&ctx)?),
                )
                    .into_response());
            }

            Some(email_authentication)
        } else {
            None
        };

    // If this registration was created from an upstream OAuth session, check
    // it is still valid and wasn't linked to a user in the meantime
    let upstream_oauth = if let Some(upstream_oauth_authorization_session_id) =
        registration.upstream_oauth_authorization_session_id
    {
        let upstream_oauth_authorization_session = repo
            .upstream_oauth_session()
            .lookup(upstream_oauth_authorization_session_id)
            .await?
            .context("Could not load the upstream OAuth authorization session")
            .map_err(InternalError::from_anyhow)?;

        let link_id = upstream_oauth_authorization_session
            .link_id()
            // This should not happen, the session is associated with the user
            // registration once the link was already created
            .context("Authorization session has no upstream link associated with it")
            .map_err(InternalError::from_anyhow)?;

        if upstream_oauth_authorization_session.is_consumed() {
            // This means an authorization session was used to create multiple
            // user registrations. This can happen if the user goes back in
            // their navigation history and basically registers twice. We also
            // used to consume the session earlier in the flow, so it's also
            // possible that it happens during the rollout of that version. This
            // is not going to happen often enough to have a dedicated page
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "The upstream authorization session was already used. Try registering again"
            )));
        }

        let upstream_oauth_link = repo
            .upstream_oauth_link()
            .lookup(link_id)
            .await?
            .context("Could not load the upstream OAuth link")
            .map_err(InternalError::from_anyhow)?;

        if upstream_oauth_link.user_id.is_some() {
            // This means the link was already associated to a user. This could
            // in theory happen if the same user registers concurrently, but
            // this is not going to happen often enough to have a dedicated page
            return Err(InternalError::from_anyhow(anyhow::anyhow!(
                "The upstream identity was already linked to a user. Try logging in again"
            )));
        }

        Some((upstream_oauth_authorization_session, upstream_oauth_link))
    } else {
        None
    };

    // Check that the display name is set
    if registration.display_name.is_none() {
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::RegisterDisplayName::new(registration.id)),
        )
            .into_response());
    }

    // Everything is good, let's complete the registration
    let registration = repo
        .user_registration()
        .complete(&clock, registration)
        .await?;

    // If we used a registration token, we need to mark it as used
    if let Some(registration_token) = registration_token {
        repo.user_registration_token()
            .use_token(&clock, registration_token)
            .await?;
    }

    // Consume the registration session
    let cookie_jar = registrations
        .consume_session(&registration)?
        .save(cookie_jar, &clock);

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

    if let Some(email_authentication) = email_authentication {
        repo.user_email()
            .add(&mut rng, &clock, &user, email_authentication.email)
            .await?;
    }

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

        PASSWORD_REGISTER_COUNTER.add(1, &[]);
    }

    if let Some((upstream_session, upstream_link)) = upstream_oauth {
        let upstream_session = repo
            .upstream_oauth_session()
            .consume(&clock, upstream_session, &user_session)
            .await?;

        repo.upstream_oauth_link()
            .associate_to_user(&upstream_link, &user)
            .await?;

        repo.browser_session()
            .authenticate_with_upstream(&mut rng, &clock, &user_session, &upstream_session)
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
    )
        .into_response());
}
