// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::BTreeMap, process::ExitCode};

use anyhow::Context;
use chrono::Duration;
use clap::{ArgAction, CommandFactory, Parser};
use console::{Alignment, Style, Term, pad_str, style};
use dialoguer::{Confirm, FuzzySelect, Input, Password, theme::ColorfulTheme};
use figment::Figment;
use mas_config::{
    ConfigurationSection, ConfigurationSectionExt, DatabaseConfig, MatrixConfig, PasswordsConfig,
};
use mas_data_model::{Device, TokenType, Ulid, UpstreamOAuthProvider, User};
use mas_email::Address;
use mas_matrix::HomeserverConnection;
use mas_storage::{
    Clock, RepositoryAccess, SystemClock,
    compat::{CompatAccessTokenRepository, CompatSessionFilter, CompatSessionRepository},
    oauth2::OAuth2SessionFilter,
    queue::{
        DeactivateUserJob, ProvisionUserJob, QueueJobRepositoryExt as _, ReactivateUserJob,
        SyncDevicesJob,
    },
    user::{BrowserSessionFilter, UserEmailRepository, UserPasswordRepository, UserRepository},
};
use mas_storage_pg::{DatabaseError, PgRepository};
use rand::{
    RngCore, SeedableRng,
    distributions::{Alphanumeric, DistString as _},
};
use sqlx::{Acquire, types::Uuid};
use tracing::{error, info, info_span, warn};
use zeroize::Zeroizing;

use crate::util::{
    database_connection_from_config, homeserver_connection_from_config,
    password_manager_from_config,
};

const USER_ATTRIBUTES_HEADING: &str = "User attributes";

#[derive(Debug, Clone)]
struct UpstreamProviderMapping {
    upstream_provider_id: Ulid,
    subject: String,
}

fn parse_upstream_provider_mapping(s: &str) -> Result<UpstreamProviderMapping, anyhow::Error> {
    let (id, subject) = s.split_once(':').context("Invalid format")?;
    let upstream_provider_id = id.parse().context("Invalid upstream provider ID")?;
    let subject = subject.to_owned();

    Ok(UpstreamProviderMapping {
        upstream_provider_id,
        subject,
    })
}

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Add an email address to the specified user
    AddEmail { username: String, email: String },

    /// (DEPRECATED) Mark email address as verified
    VerifyEmail { username: String, email: String },

    /// Set a user password
    SetPassword {
        username: String,
        password: String,
        /// Don't enforce that the password provided is above the minimum
        /// configured complexity.
        #[clap(long)]
        ignore_complexity: bool,
    },

    /// Issue a compatibility token
    IssueCompatibilityToken {
        /// User for which to issue the token
        username: String,

        /// Device ID to set in the token. If not specified, a random device ID
        /// will be generated.
        device_id: Option<String>,

        /// Whether that token should be admin
        #[arg(long = "yes-i-want-to-grant-synapse-admin-privileges")]
        admin: bool,
    },

    /// Create a new user registration token
    IssueUserRegistrationToken {
        /// Specific token string to use. If not provided, a random token will
        /// be generated.
        #[arg(long)]
        token: Option<String>,

        /// Maximum number of times this token can be used.
        /// If not provided, the token can be used only once, unless the
        /// `--unlimited` flag is set.
        #[arg(long, group = "token-usage-limit")]
        usage_limit: Option<u32>,

        /// Allow the token to be used an unlimited number of times.
        #[arg(long, action = ArgAction::SetTrue, group = "token-usage-limit")]
        unlimited: bool,

        /// Time in seconds after which the token expires.
        /// If not provided, the token never expires.
        #[arg(long)]
        expires_in: Option<u32>,
    },

    /// Trigger a provisioning job for all users
    ProvisionAllUsers,

    /// Kill all sessions for a user
    KillSessions {
        /// User for which to kill sessions
        username: String,

        /// Do a dry run
        #[arg(long)]
        dry_run: bool,
    },

    /// Lock a user
    LockUser {
        /// User to lock
        username: String,

        /// Whether to deactivate the user
        #[arg(long)]
        deactivate: bool,
    },

    /// Unlock a user
    UnlockUser {
        /// User to unlock
        username: String,

        /// Whether to reactivate the user if it had been deactivated
        #[arg(long)]
        reactivate: bool,
    },

    /// Register a user
    ///
    /// This will interactively prompt for the user's attributes unless the
    /// `--yes` flag is set. It bypasses any policy check on the password,
    /// email, etc.
    RegisterUser {
        /// Username to register
        #[arg(help_heading = USER_ATTRIBUTES_HEADING, required_if_eq("yes", "true"))]
        username: Option<String>,

        /// Password to set
        #[arg(short, long, help_heading = USER_ATTRIBUTES_HEADING)]
        password: Option<String>,

        /// Email to add
        #[arg(short, long = "email", action = ArgAction::Append, help_heading = USER_ATTRIBUTES_HEADING)]
        emails: Vec<Address>,

        /// Upstream OAuth 2.0 provider mapping to add
        #[arg(
            short = 'm',
            long = "upstream-provider-mapping",
            value_parser = parse_upstream_provider_mapping,
            action = ArgAction::Append,
            value_name = "UPSTREAM_PROVIDER_ID:SUBJECT",
            help_heading = USER_ATTRIBUTES_HEADING
        )]
        upstream_provider_mappings: Vec<UpstreamProviderMapping>,

        /// Make the user an admin
        #[arg(short, long, action = ArgAction::SetTrue, group = "admin-flag", help_heading = USER_ATTRIBUTES_HEADING)]
        admin: bool,

        /// Make the user not an admin
        #[arg(short = 'A', long, action = ArgAction::SetTrue, group = "admin-flag", help_heading = USER_ATTRIBUTES_HEADING)]
        no_admin: bool,

        // Don't ask questions, just do it
        #[arg(short, long, action = ArgAction::SetTrue)]
        yes: bool,

        /// Set the user's display name
        #[arg(short, long, help_heading = USER_ATTRIBUTES_HEADING)]
        display_name: Option<String>,
        /// Don't enforce that the password provided is above the minimum
        /// configured complexity.
        #[clap(long)]
        ignore_password_complexity: bool,
    },
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;
        let clock = SystemClock::default();
        // XXX: we should disallow SeedableRng::from_entropy
        let mut rng = rand_chacha::ChaChaRng::from_entropy();

        match self.subcommand {
            SC::SetPassword {
                username,
                password,
                ignore_complexity,
            } => {
                let _span =
                    info_span!("cli.manage.set_password", user.username = %username).entered();

                let database_config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let passwords_config = PasswordsConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;

                let mut conn = database_connection_from_config(&database_config).await?;
                let password_manager = password_manager_from_config(&passwords_config).await?;

                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);
                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                if !ignore_complexity && !password_manager.is_password_complex_enough(&password)? {
                    error!("That password is too weak.");
                    return Ok(ExitCode::from(1));
                }

                let password = Zeroizing::new(password);

                let (version, hashed_password) = password_manager.hash(&mut rng, password).await?;

                repo.user_password()
                    .add(&mut rng, &clock, &user, version, hashed_password, None)
                    .await?;

                info!(%user.id, %user.username, "Password changed");
                repo.into_inner().commit().await?;

                Ok(ExitCode::SUCCESS)
            }

            SC::AddEmail { username, email } => {
                let _span = info_span!(
                    "cli.manage.add_email",
                    user.username = username,
                    user_email.email = email
                )
                .entered();

                let database_config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                // Find any existing email address
                let existing_email = repo.user_email().find(&user, &email).await?;
                let email = if let Some(email) = existing_email {
                    info!(%email.id, "Email already exists, makring as verified");
                    email
                } else {
                    repo.user_email()
                        .add(&mut rng, &clock, &user, email)
                        .await?
                };

                repo.into_inner().commit().await?;
                info!(
                    %user.id,
                    %user.username,
                    %email.id,
                    %email.email,
                    "Email added"
                );

                Ok(ExitCode::SUCCESS)
            }

            SC::VerifyEmail { username, email } => {
                let _span = info_span!(
                    "cli.manage.verify_email",
                    user.username = username,
                    user_email.email = email
                )
                .entered();

                tracing::warn!(
                    "The 'verify-email' command is deprecated and will be removed in a future version. Use 'add-email' instead."
                );

                Ok(ExitCode::SUCCESS)
            }

            SC::IssueCompatibilityToken {
                username,
                admin,
                device_id,
            } => {
                let database_config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let matrix_config =
                    MatrixConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
                let http_client = mas_http::reqwest_client();
                let homeserver =
                    homeserver_connection_from_config(&matrix_config, http_client).await?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                let device = if let Some(device_id) = device_id {
                    device_id.into()
                } else {
                    Device::generate(&mut rng)
                };

                if let Err(e) = homeserver
                    .upsert_device(&user.username, device.as_str(), None)
                    .await
                {
                    error!(
                        error = &*e,
                        "Could not create the device on the homeserver, aborting"
                    );

                    // Schedule a device sync job to remove the potential leftover device
                    repo.queue_job()
                        .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
                        .await?;

                    repo.into_inner().commit().await?;
                    return Ok(ExitCode::FAILURE);
                }

                let compat_session = repo
                    .compat_session()
                    .add(&mut rng, &clock, &user, device, None, admin, None)
                    .await?;

                let token = TokenType::CompatAccessToken.generate(&mut rng);

                let compat_access_token = repo
                    .compat_access_token()
                    .add(&mut rng, &clock, &compat_session, token, None)
                    .await?;

                repo.into_inner().commit().await?;

                info!(
                    %compat_access_token.id,
                    %compat_session.id,
                    compat_session.device = compat_session.device.map(tracing::field::display),
                    %user.id,
                    %user.username,
                    "Compatibility token issued: {}", compat_access_token.token
                );

                Ok(ExitCode::SUCCESS)
            }

            SC::IssueUserRegistrationToken {
                token,
                usage_limit,
                unlimited,
                expires_in,
            } => {
                let _span = info_span!("cli.manage.add_user_registration_token").entered();

                let usage_limit = match (usage_limit, unlimited) {
                    (Some(usage_limit), false) => Some(usage_limit),
                    (None, false) => Some(1),
                    (None, true) => None,
                    (Some(_), true) => unreachable!(), // This should be handled by the clap group
                };

                let database_config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                // Calculate expiration time if provided
                let expires_at =
                    expires_in.map(|seconds| clock.now() + Duration::seconds(seconds.into()));

                // Generate a token if not provided
                let token_str = token.unwrap_or_else(|| Alphanumeric.sample_string(&mut rng, 12));

                // Create the token
                let registration_token = repo
                    .user_registration_token()
                    .add(&mut rng, &clock, token_str, usage_limit, expires_at)
                    .await?;

                repo.into_inner().commit().await?;

                info!(%registration_token.id, "Created user registration token: {}", registration_token.token);

                Ok(ExitCode::SUCCESS)
            }

            SC::ProvisionAllUsers => {
                let _span = info_span!("cli.manage.provision_all_users").entered();
                let database_config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let mut txn = conn.begin().await?;

                // TODO: do some pagination here
                let ids: Vec<Uuid> = sqlx::query_scalar("SELECT user_id FROM users")
                    .fetch_all(&mut *txn)
                    .await?;

                let mut repo = PgRepository::from_conn(txn);

                for id in ids {
                    let id = id.into();
                    info!(user.id = %id, "Scheduling provisioning job");
                    let job = ProvisionUserJob::new_for_id(id);
                    repo.queue_job().schedule_job(&mut rng, &clock, job).await?;
                }

                repo.into_inner().commit().await?;

                Ok(ExitCode::SUCCESS)
            }

            SC::KillSessions { username, dry_run } => {
                let _span =
                    info_span!("cli.manage.kill_sessions", user.username = username).entered();
                let database_config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                let filter = CompatSessionFilter::new().for_user(&user).active_only();
                let affected = if dry_run {
                    repo.compat_session().count(filter).await?
                } else {
                    repo.compat_session().finish_bulk(&clock, filter).await?
                };

                match affected {
                    0 => info!("No active compatibility sessions to end"),
                    1 => info!("Ended 1 active compatibility session"),
                    _ => info!("Ended {affected} active compatibility sessions"),
                }

                let filter = OAuth2SessionFilter::new().for_user(&user).active_only();
                let affected = if dry_run {
                    repo.oauth2_session().count(filter).await?
                } else {
                    repo.oauth2_session().finish_bulk(&clock, filter).await?
                };

                match affected {
                    0 => info!("No active compatibility sessions to end"),
                    1 => info!("Ended 1 active OAuth 2.0 session"),
                    _ => info!("Ended {affected} active OAuth 2.0 sessions"),
                }

                let filter = BrowserSessionFilter::new().for_user(&user).active_only();
                let affected = if dry_run {
                    repo.browser_session().count(filter).await?
                } else {
                    repo.browser_session().finish_bulk(&clock, filter).await?
                };

                match affected {
                    0 => info!("No active browser sessions to end"),
                    1 => info!("Ended 1 active browser session"),
                    _ => info!("Ended {affected} active browser sessions"),
                }

                // Schedule a job to sync the devices of the user with the homeserver
                warn!("Scheduling job to sync devices for the user");
                repo.queue_job()
                    .schedule_job(&mut rng, &clock, SyncDevicesJob::new(&user))
                    .await?;

                let txn = repo.into_inner();
                if dry_run {
                    info!("Dry run, not saving");
                    txn.rollback().await?;
                } else {
                    txn.commit().await?;
                }

                Ok(ExitCode::SUCCESS)
            }

            SC::LockUser {
                username,
                deactivate,
            } => {
                let _span = info_span!("cli.manage.lock_user", user.username = username).entered();
                let config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let mut conn = database_connection_from_config(&config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                info!(%user.id, "Locking user");

                // Even though the deactivation job will lock the user, we lock it here in case
                // the worker is not running, as we don't have a good way to run a job
                // synchronously yet.
                let user = repo.user().lock(&clock, user).await?;

                if deactivate {
                    warn!(%user.id, "Scheduling user deactivation");
                    repo.queue_job()
                        .schedule_job(&mut rng, &clock, DeactivateUserJob::new(&user, false))
                        .await?;
                }

                repo.into_inner().commit().await?;

                Ok(ExitCode::SUCCESS)
            }

            SC::UnlockUser {
                username,
                reactivate,
            } => {
                let _span =
                    info_span!("cli.manage.unlock_user", user.username = username).entered();
                let config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let mut conn = database_connection_from_config(&config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                let user = repo
                    .user()
                    .find_by_username(&username)
                    .await?
                    .context("User not found")?;

                if reactivate {
                    warn!(%user.id, "Scheduling user reactivation");
                    repo.queue_job()
                        .schedule_job(&mut rng, &clock, ReactivateUserJob::new(&user))
                        .await?;
                } else {
                    repo.user().unlock(user).await?;
                }

                repo.into_inner().commit().await?;

                Ok(ExitCode::SUCCESS)
            }

            SC::RegisterUser {
                username,
                password,
                emails,
                upstream_provider_mappings,
                admin,
                no_admin,
                display_name,
                yes,
                ignore_password_complexity,
            } => {
                let http_client = mas_http::reqwest_client();
                let password_config = PasswordsConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let database_config = DatabaseConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let matrix_config =
                    MatrixConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;

                let password_manager = password_manager_from_config(&password_config).await?;
                let homeserver =
                    homeserver_connection_from_config(&matrix_config, http_client).await?;
                let mut conn = database_connection_from_config(&database_config).await?;
                let txn = conn.begin().await?;
                let mut repo = PgRepository::from_conn(txn);

                if let Some(password) = &password {
                    if !ignore_password_complexity
                        && !password_manager.is_password_complex_enough(password)?
                    {
                        error!("That password is too weak.");
                        return Ok(ExitCode::from(1));
                    }
                }

                // If the username is provided, check if it's available and normalize it.
                let localpart = if let Some(username) = username {
                    check_and_normalize_username(&username, &mut repo, &homeserver)
                        .await?
                        .to_owned()
                } else {
                    // Else we prompt for one until we get a valid one.
                    loop {
                        let username = tokio::task::spawn_blocking(|| {
                            Input::<String>::with_theme(&ColorfulTheme::default())
                                .with_prompt("Username")
                                .interact_text()
                        })
                        .await??;

                        match check_and_normalize_username(&username, &mut repo, &homeserver).await
                        {
                            Ok(localpart) => break localpart.to_owned(),
                            Err(e) => {
                                warn!("Invalid username: {e}");
                            }
                        }
                    }
                };

                // Load all the upstream providers
                let upstream_providers: BTreeMap<_, _> = repo
                    .upstream_oauth_provider()
                    .all_enabled()
                    .await?
                    .into_iter()
                    .map(|provider| (provider.id, provider))
                    .collect();

                let upstream_provider_mappings = upstream_provider_mappings
                    .into_iter()
                    .map(|mapping| {
                        (
                            &upstream_providers[&mapping.upstream_provider_id],
                            mapping.subject,
                        )
                    })
                    .collect();

                let admin = match (admin, no_admin) {
                    (false, false) => None,
                    (true, false) => Some(true),
                    (false, true) => Some(false),
                    _ => unreachable!("This should be handled by the clap group"),
                };

                // Hash the password if it's provided
                let hashed_password = if let Some(password) = password {
                    let password = Zeroizing::new(password);
                    Some(password_manager.hash(&mut rng, password).await?)
                } else {
                    None
                };

                let mut req = UserCreationRequest {
                    username: localpart,
                    hashed_password,
                    emails,
                    upstream_provider_mappings,
                    display_name,
                    admin,
                };

                let term = Term::buffered_stdout();
                loop {
                    req.show(&term, &homeserver)?;

                    // If we're in `yes` mode, we don't prompt for actions
                    if yes {
                        break;
                    }

                    term.write_line(&format!(
                        "\n{msg}:\n\n  {cmd}\n",
                        msg = style("Non-interactive equivalent to create this user").bold(),
                        cmd = style(UserCreationCommand(&req)).underlined(),
                    ))?;

                    term.flush()?;

                    let action = req
                        .prompt_action(
                            password_manager.is_enabled(),
                            !upstream_providers.is_empty(),
                        )
                        .await?
                        .context("Aborted")?;

                    match action {
                        Action::CreateUser => break,
                        Action::ChangeUsername => {
                            req.username = loop {
                                let current_username = req.username.clone();
                                let username = tokio::task::spawn_blocking(|| {
                                    Input::<String>::with_theme(&ColorfulTheme::default())
                                        .with_prompt("Username")
                                        .with_initial_text(current_username)
                                        .interact_text()
                                })
                                .await??;

                                match check_and_normalize_username(
                                    &username,
                                    &mut repo,
                                    &homeserver,
                                )
                                .await
                                {
                                    Ok(localpart) => break localpart.to_owned(),
                                    Err(e) => {
                                        warn!("Invalid username: {e}");
                                    }
                                }
                            };
                        }
                        Action::SetPassword => {
                            let password = tokio::task::spawn_blocking(|| {
                                Password::with_theme(&ColorfulTheme::default())
                                    .with_prompt("Password")
                                    .with_confirmation("Confirm password", "Passwords mismatching")
                                    .interact()
                            })
                            .await??;
                            let password = Zeroizing::new(password);
                            req.hashed_password =
                                Some(password_manager.hash(&mut rng, password).await?);
                        }
                        Action::SetDisplayName => {
                            let display_name = tokio::task::spawn_blocking(|| {
                                Input::<String>::with_theme(&ColorfulTheme::default())
                                    .with_prompt("Display name")
                                    .interact()
                            })
                            .await??;
                            req.display_name = Some(display_name);
                        }
                        Action::AddEmail => {
                            let email = tokio::task::spawn_blocking(|| {
                                Input::<Address>::with_theme(&ColorfulTheme::default())
                                    .with_prompt("Email")
                                    .interact_text()
                            })
                            .await??;
                            req.emails.push(email);
                        }
                        Action::SetAdmin => {
                            let admin = tokio::task::spawn_blocking(|| {
                                Confirm::with_theme(&ColorfulTheme::default())
                                    .with_prompt("Make user admin?")
                                    .interact()
                            })
                            .await??;
                            req.admin = Some(admin);
                        }
                        Action::AddUpstreamProviderMapping => {
                            let providers = upstream_providers.clone();
                            let provider_id = tokio::task::spawn_blocking(move || {
                                let providers: Vec<_> = providers.into_values().collect();
                                let human_readable_providers: Vec<_> =
                                    providers.iter().map(HumanReadable).collect();
                                FuzzySelect::with_theme(&ColorfulTheme::default())
                                    .with_prompt("Upstream provider")
                                    .items(&human_readable_providers)
                                    .default(0)
                                    .interact()
                                    .map(move |selected| providers[selected].id)
                            })
                            .await??;
                            let provider = &upstream_providers[&provider_id];

                            let subject = tokio::task::spawn_blocking(|| {
                                Input::<String>::with_theme(&ColorfulTheme::default())
                                    .with_prompt("Subject")
                                    .interact()
                            })
                            .await??;

                            req.upstream_provider_mappings.push((provider, subject));
                        }
                    }
                }

                if req.emails.is_empty() {
                    warn!("No email address provided, user will need to add one");
                }

                let confirmation = if yes {
                    true
                } else {
                    tokio::task::spawn_blocking(|| {
                        Confirm::with_theme(&ColorfulTheme::default())
                            .with_prompt("Confirm?")
                            .interact()
                    })
                    .await??
                };

                if confirmation {
                    let user = req.do_register(&mut repo, &mut rng, &clock).await?;
                    repo.into_inner().commit().await?;
                    info!(%user.id, "User registered");
                } else {
                    warn!("Aborted");
                }

                Ok(ExitCode::SUCCESS)
            }
        }
    }
}

/// A wrapper to display some objects differently
#[derive(Debug, Clone, Copy)]
struct HumanReadable<T>(T);

impl std::fmt::Display for HumanReadable<&UpstreamOAuthProvider> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let provider = self.0;
        if let Some(human_name) = &provider.human_name {
            write!(f, "{} ({})", human_name, provider.id)
        } else if let Some(issuer) = &provider.issuer {
            write!(f, "{} ({})", issuer, provider.id)
        } else {
            write!(f, "{}", provider.id)
        }
    }
}

async fn check_and_normalize_username<'a>(
    localpart_or_mxid: &'a str,
    repo: &mut dyn RepositoryAccess<Error = DatabaseError>,
    homeserver: &dyn HomeserverConnection,
) -> anyhow::Result<&'a str> {
    // XXX: this is a very basic MXID to localpart conversion
    // Strip any leading '@'
    let mut localpart = localpart_or_mxid.trim_start_matches('@');

    // Strip any trailing ':homeserver'
    if let Some(index) = localpart.find(':') {
        localpart = &localpart[..index];
    }

    if localpart.is_empty() {
        return Err(anyhow::anyhow!("Username cannot be empty"));
    }

    if repo.user().exists(localpart).await? {
        return Err(anyhow::anyhow!("User already exists"));
    }

    if !homeserver.is_localpart_available(localpart).await? {
        return Err(anyhow::anyhow!("Username not available on homeserver"));
    }

    Ok(localpart)
}

struct UserCreationRequest<'a> {
    username: String,
    hashed_password: Option<(u16, String)>,
    emails: Vec<Address>,
    upstream_provider_mappings: Vec<(&'a UpstreamOAuthProvider, String)>,
    display_name: Option<String>,
    admin: Option<bool>,
}

impl UserCreationRequest<'_> {
    // Get a list of the possible actions
    fn possible_actions(
        &self,
        has_password_auth: bool,
        has_upstream_providers: bool,
    ) -> Vec<Action> {
        let mut actions = vec![Action::CreateUser, Action::ChangeUsername, Action::AddEmail];

        if has_password_auth && self.hashed_password.is_none() {
            actions.push(Action::SetPassword);
        }

        if has_upstream_providers {
            actions.push(Action::AddUpstreamProviderMapping);
        }

        if self.admin.is_none() {
            actions.push(Action::SetAdmin);
        }

        if self.display_name.is_none() {
            actions.push(Action::SetDisplayName);
        }

        actions
    }

    /// Prompt for the next action
    async fn prompt_action(
        &self,
        has_password_auth: bool,
        has_upstream_providers: bool,
    ) -> anyhow::Result<Option<Action>> {
        let actions = self.possible_actions(has_password_auth, has_upstream_providers);
        tokio::task::spawn_blocking(move || {
            let index = FuzzySelect::with_theme(&ColorfulTheme::default())
                .with_prompt("What do you want to do next? (<Esc> to abort)")
                .items(&actions)
                .default(0)
                .interact_opt()?;
            Ok(index.map(|index| actions[index]))
        })
        .await?
    }

    /// Show the user creation request in a human-readable format
    fn show(&self, term: &Term, homeserver: &dyn HomeserverConnection) -> std::io::Result<()> {
        let value_style = Style::new().green();
        let key_style = Style::new().bold();
        let warning_style = Style::new().italic().red().bright();
        let username = &self.username;
        let mxid = homeserver.mxid(username);

        term.write_line(&style("User attributes").bold().underlined().to_string())?;

        macro_rules! display {
            ($key:expr, $value:expr) => {
                term.write_line(&format!(
                    "{key}: {value}",
                    key = key_style.apply_to(pad_str($key, 17, Alignment::Right, None)),
                    value = value_style.apply_to($value)
                ))?;
            };
        }

        display!("Username", username);
        display!("Matrix ID", mxid);
        if let Some(display_name) = &self.display_name {
            display!("Display name", display_name);
        }

        if self.hashed_password.is_some() {
            display!("Password", "********");
        }

        for (provider, subject) in &self.upstream_provider_mappings {
            let provider = HumanReadable(*provider);
            display!("Upstream account", format!("{provider} : {subject:?}"));
        }

        for email in &self.emails {
            display!("Email", email);
        }

        if self.emails.is_empty() {
            term.write_line(
                &warning_style
                    .apply_to("No email address provided, user will be prompted to add one")
                    .to_string(),
            )?;
        }

        if self.hashed_password.is_none() && self.upstream_provider_mappings.is_empty() {
            term.write_line(
                &warning_style.apply_to("No password or upstream provider mapping provided, user will not be able to log in")
                    .to_string(),
            )?;
        }

        if let Some(admin) = self.admin {
            display!("Can request admin", admin);
        }

        term.flush()?;

        Ok(())
    }

    /// Submit the user creation request
    async fn do_register<E: std::error::Error + Send + Sync + 'static>(
        self,
        repo: &mut dyn RepositoryAccess<Error = E>,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
    ) -> Result<User, E> {
        let Self {
            username,
            hashed_password,
            emails,
            upstream_provider_mappings,
            display_name,
            admin,
        } = self;
        let mut user = repo.user().add(rng, clock, username).await?;

        if let Some((version, hashed_password)) = hashed_password {
            repo.user_password()
                .add(rng, clock, &user, version, hashed_password, None)
                .await?;
        }

        for email in emails {
            repo.user_email()
                .add(rng, clock, &user, email.to_string())
                .await?;
        }

        for (provider, subject) in upstream_provider_mappings {
            // Note that we don't pass a human_account_name here, as we don't ask for it
            let link = repo
                .upstream_oauth_link()
                .add(rng, clock, provider, subject, None)
                .await?;

            repo.upstream_oauth_link()
                .associate_to_user(&link, &user)
                .await?;
        }

        if let Some(admin) = admin {
            user = repo.user().set_can_request_admin(user, admin).await?;
        }

        let mut provision_job = ProvisionUserJob::new(&user);
        if let Some(display_name) = display_name {
            provision_job = provision_job.set_display_name(display_name);
        }

        repo.queue_job()
            .schedule_job(rng, clock, provision_job)
            .await?;

        Ok(user)
    }
}

#[derive(Debug, Clone, Copy)]
enum Action {
    CreateUser,
    ChangeUsername,
    SetPassword,
    SetDisplayName,
    AddEmail,
    SetAdmin,
    AddUpstreamProviderMapping,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::CreateUser => write!(f, "Create the user"),
            Action::ChangeUsername => write!(f, "Change the username"),
            Action::SetPassword => write!(f, "Set a password"),
            Action::AddEmail => write!(f, "Add email"),
            Action::SetDisplayName => write!(f, "Set a display name"),
            Action::SetAdmin => write!(f, "Set the admin status"),
            Action::AddUpstreamProviderMapping => write!(f, "Add upstream provider mapping"),
        }
    }
}

/// A wrapper to display the user creation request as a command
struct UserCreationCommand<'a>(&'a UserCreationRequest<'a>);

impl std::fmt::Display for UserCreationCommand<'_> {
    fn fmt(&self, w: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let command = super::Options::command();
        let manage = command.find_subcommand("manage").unwrap();
        let register_user = manage.find_subcommand("register-user").unwrap();
        let yes_arg = &register_user[&clap::Id::from("yes")];
        let password_arg = &register_user[&clap::Id::from("password")];
        let email_arg = &register_user[&clap::Id::from("emails")];
        let upstream_provider_mapping_arg =
            &register_user[&clap::Id::from("upstream_provider_mappings")];
        let display_name_arg = &register_user[&clap::Id::from("display_name")];
        let admin_arg = &register_user[&clap::Id::from("admin")];
        let no_admin_arg = &register_user[&clap::Id::from("no_admin")];

        write!(
            w,
            "{} {} {} --{} {}",
            command.get_name(),
            manage.get_name(),
            register_user.get_name(),
            yes_arg.get_long().unwrap(),
            self.0.username,
        )?;

        for email in &self.0.emails {
            let email: &str = email.as_ref();
            write!(w, " --{} {email:?}", email_arg.get_long().unwrap())?;
        }

        if let Some(display_name) = &self.0.display_name {
            write!(
                w,
                " --{} {:?}",
                display_name_arg.get_long().unwrap(),
                display_name
            )?;
        }

        if self.0.hashed_password.is_some() {
            write!(w, " --{} $PASSWORD", password_arg.get_long().unwrap())?;
        }

        for (provider, subject) in &self.0.upstream_provider_mappings {
            let mapping = format!("{}:{}", provider.id, subject);
            write!(
                w,
                " --{} {mapping:?}",
                upstream_provider_mapping_arg.get_long().unwrap(),
            )?;
        }

        match self.0.admin {
            Some(true) => write!(w, " --{}", admin_arg.get_long().unwrap())?,
            Some(false) => write!(w, " --{}", no_admin_arg.get_long().unwrap())?,
            None => {}
        }

        Ok(())
    }
}
