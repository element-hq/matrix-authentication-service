// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Verification and resolution of the `id_token_hint` authorization request
//! parameter.

use std::collections::HashMap;

use mas_data_model::{BrowserSession, Clock, User};
use mas_jose::{
    claims::{self, TimeOptions},
    jwt::Jwt,
};
use mas_keystore::Keystore;
use mas_router::UrlBuilder;
use mas_storage::{BoxRepository, RepositoryAccess, RepositoryError, user::UserEmailRepository};
use serde_json::Value;
use ulid::Ulid;

use crate::views::shared::{LoginHint, parse_login_hint};

/// Decide whether the active browser session matches the identity the client
/// requested (on an authorization grant or a login session).
///
/// The match key is the **user**, not the session: a stale `sid` whose user is
/// still logged in is a match. The trust ladder mirrors §4 of the design:
///
/// * a verified `id_token_hint` target (`target_user_id`) is **trusted** and
///   compared by user id;
/// * otherwise an untrusted `login_hint` is parsed and compared against the
///   *current* session's own data only (we never look up the hinted account):
///   an `mxid:` hint matches on localpart + homeserver, a bare email matches
///   iff the current user owns that email;
/// * an unparseable or absent hint is treated as no constraint (a match).
///
/// Returns `Ok(true)` when there is no mismatch (proceed with the flow),
/// `Ok(false)` when the active session is a different account than requested.
pub(crate) async fn session_matches_requested_identity(
    repo: &mut BoxRepository,
    homeserver: &str,
    target_user_id: Option<Ulid>,
    login_hint: Option<&str>,
    session: &BrowserSession,
) -> Result<bool, RepositoryError> {
    // Trusted target wins: compare by user id.
    if let Some(target) = target_user_id {
        return Ok(session.user.id == target);
    }

    // Otherwise fall back to the untrusted `login_hint`, compared only against
    // the current session's own data.
    let Some(login_hint) = login_hint else {
        return Ok(true);
    };

    match parse_login_hint(login_hint, homeserver) {
        // `parse_login_hint` only resolves mxids on our own homeserver, so
        // comparing localparts is enough.
        LoginHint::Mxid(mxid) => Ok(mxid.localpart() == session.user.username),
        LoginHint::Email(email) => {
            // Look up the email on the *current* user only — their own data.
            let found = repo
                .user_email()
                .find(&session.user, email.as_ref())
                .await?;
            Ok(found.is_some())
        }
        // Unparseable hint (including an mxid on another homeserver): no
        // constraint we can act on, treat as a match.
        LoginHint::None => Ok(true),
    }
}

/// The resolved outcome of verifying an `id_token_hint`.
pub(crate) struct ResolvedHint {
    /// The user identified by the token's `sub` claim.
    pub user: User,

    /// The browser session identified by the token's `sid` claim, if it was
    /// present and still resolves to an existing session for the same user.
    pub browser_session: Option<BrowserSession>,
}

/// Verify a downstream-supplied `id_token_hint` and resolve it to a user (and,
/// when possible, the browser session that issued it).
///
/// An `id_token_hint` is advisory per the OIDC spec, so any condition that
/// means "this isn't a hint we can act on" — a malformed JWT, a bad signature,
/// the wrong issuer, an unknown user, a malformed `sid` — resolves to
/// `Ok(None)`, and the caller behaves as if no hint had been given. Only
/// genuine infrastructure failures (a database error) surface as `Err`.
///
/// Unlike a normal ID token verification, this deliberately:
///
/// * does **not** check the `aud` claim — a client may legitimately present a
///   token originally issued to a *different* client (paired companion apps,
///   reinstalls, hand-offs), and an ID token discloses nothing the holder
///   didn't already have; a valid signature plus our own `iss` is enough to
///   confirm we minted it; and
/// * **allows an expired `exp`** — the whole point of the hint is that the
///   original session is likely gone.
pub(crate) async fn resolve_id_token_hint(
    repo: &mut BoxRepository,
    clock: &impl Clock,
    keystore: &Keystore,
    url_builder: &UrlBuilder,
    raw: &str,
) -> Result<Option<ResolvedHint>, RepositoryError> {
    // Parse the JWT.
    let Ok(token): Result<Jwt<HashMap<String, Value>>, _> = raw.try_into() else {
        tracing::debug!("Ignoring id_token_hint: not a well-formed JWT");
        return Ok(None);
    };

    // Verify the signature against our own keys: we minted it, so it must
    // verify against our keystore.
    if token.verify_with_jwks(&keystore.public_jwks()).is_err() {
        tracing::debug!("Ignoring id_token_hint: signature did not verify against our keys");
        return Ok(None);
    }

    let (_header, mut claims) = token.into_parts();

    // The issuer must be us. Refuse anything else outright.
    let issuer = url_builder.oidc_issuer().to_string();
    if claims::ISS
        .extract_required_with_options(&mut claims, issuer.as_str())
        .is_err()
    {
        tracing::debug!("Ignoring id_token_hint: issuer mismatch");
        return Ok(None);
    }

    // `iat`, if present, must not be in the future (beyond the usual small
    // skew). We deliberately do not check `exp`: the hint is most useful
    // precisely when the token has expired.
    let time_options = TimeOptions::new(clock.now());
    if claims::IAT
        .extract_optional_with_options(&mut claims, &time_options)
        .is_err()
    {
        tracing::debug!("Ignoring id_token_hint: iat is in the future");
        return Ok(None);
    }

    // Resolve the user from the `sub` claim. For MAS-issued tokens, `sub` is the
    // user's ULID rendered as a string.
    let Ok(Some(sub)) = claims::SUB.extract_optional(&mut claims) else {
        tracing::debug!("Ignoring id_token_hint: missing or invalid sub claim");
        return Ok(None);
    };
    let Ok(user_id) = sub.parse::<Ulid>() else {
        tracing::debug!("Ignoring id_token_hint: sub is not a ULID");
        return Ok(None);
    };
    let Some(user) = repo.user().lookup(user_id).await? else {
        tracing::debug!("Ignoring id_token_hint: sub does not resolve to a known user");
        return Ok(None);
    };

    // Resolve the browser session from the `sid` claim, if present. A `sid` that
    // resolves to a session belonging to a *different* user means the token is
    // malformed — refuse the whole hint rather than silently downgrading.
    let browser_session = match claims::SID.extract_optional(&mut claims) {
        Ok(Some(sid)) => {
            let Ok(session_id) = sid.parse::<Ulid>() else {
                tracing::debug!("Ignoring id_token_hint: sid is not a ULID");
                return Ok(None);
            };
            match repo.browser_session().lookup(session_id).await? {
                Some(session) if session.user.id == user.id => Some(session),
                Some(_) => {
                    tracing::debug!(
                        "Ignoring id_token_hint: sid resolves to a session for another user"
                    );
                    return Ok(None);
                }
                None => None,
            }
        }
        Ok(None) => None,
        Err(_) => {
            tracing::debug!("Ignoring id_token_hint: invalid sid claim");
            return Ok(None);
        }
    };

    Ok(Some(ResolvedHint {
        user,
        browser_session,
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Duration;
    use mas_data_model::Clock;
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_jose::{
        claims,
        jwt::{JsonWebSignatureHeader, Jwt},
    };
    use serde_json::Value;
    use sqlx::PgPool;
    use ulid::Ulid;

    use super::resolve_id_token_hint;
    use crate::test_utils::{TestState, setup};

    /// Build and sign an ID-token-shaped JWT against the test keystore, with
    /// the given issuer / sub / sid and an already-expired `exp`.
    fn mint_hint(state: &TestState, issuer: &str, sub: &str, sid: Option<&str>) -> String {
        let mut payload: HashMap<String, Value> = HashMap::new();
        claims::ISS.insert(&mut payload, issuer.to_owned()).unwrap();
        claims::SUB.insert(&mut payload, sub.to_owned()).unwrap();
        if let Some(sid) = sid {
            claims::SID.insert(&mut payload, sid.to_owned()).unwrap();
        }
        // Issued two hours ago, expired one hour ago: a realistic stale token.
        claims::IAT
            .insert(&mut payload, state.clock.now() - Duration::hours(2))
            .unwrap();
        claims::EXP
            .insert(&mut payload, state.clock.now() - Duration::hours(1))
            .unwrap();

        let key = state
            .key_store
            .signing_key_for_algorithm(&JsonWebSignatureAlg::Rs256)
            .unwrap();
        let signer = key
            .params()
            .signing_key_for_alg(&JsonWebSignatureAlg::Rs256)
            .unwrap();
        let header = JsonWebSignatureHeader::new(JsonWebSignatureAlg::Rs256);
        let jwt: Jwt<'static, _> =
            Jwt::sign_with_rng(&mut state.rng(), header, payload, &signer).unwrap();
        jwt.into_string()
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_resolve_valid_with_sid(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();

        let issuer = state.url_builder.oidc_issuer().to_string();
        let token = mint_hint(&state, &issuer, &user.sub, Some(&session.id.to_string()));

        let resolved = resolve_id_token_hint(
            &mut repo,
            &state.clock,
            &state.key_store,
            &state.url_builder,
            &token,
        )
        .await
        .unwrap()
        .expect("a valid, even if expired, hint should resolve");

        assert_eq!(resolved.user.id, user.id);
        assert_eq!(resolved.browser_session.map(|s| s.id), Some(session.id));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_resolve_no_sid(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let issuer = state.url_builder.oidc_issuer().to_string();
        let token = mint_hint(&state, &issuer, &user.sub, None);

        let resolved = resolve_id_token_hint(
            &mut repo,
            &state.clock,
            &state.key_store,
            &state.url_builder,
            &token,
        )
        .await
        .unwrap()
        .expect("hint without a sid should still resolve the user");

        assert_eq!(resolved.user.id, user.id);
        assert_eq!(resolved.browser_session, None);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_resolve_wrong_issuer(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let token = mint_hint(&state, "https://evil.example.com/", &user.sub, None);

        let resolved = resolve_id_token_hint(
            &mut repo,
            &state.clock,
            &state.key_store,
            &state.url_builder,
            &token,
        )
        .await
        .unwrap();

        assert!(
            resolved.is_none(),
            "a hint from another issuer must be ignored"
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_resolve_garbage(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut repo = state.repository().await.unwrap();

        let resolved = resolve_id_token_hint(
            &mut repo,
            &state.clock,
            &state.key_store,
            &state.url_builder,
            "not.a.jwt",
        )
        .await
        .unwrap();

        assert!(resolved.is_none(), "garbage input must be ignored");
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_resolve_unknown_user(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut repo = state.repository().await.unwrap();

        let issuer = state.url_builder.oidc_issuer().to_string();
        // A well-formed, correctly-signed token for a user that does not exist.
        let token = mint_hint(&state, &issuer, &Ulid::nil().to_string(), None);

        let resolved = resolve_id_token_hint(
            &mut repo,
            &state.clock,
            &state.key_store,
            &state.url_builder,
            &token,
        )
        .await
        .unwrap();

        assert!(
            resolved.is_none(),
            "a hint for an unknown user must be ignored"
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_resolve_sid_for_other_user(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut repo = state.repository().await.unwrap();

        let alice = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let bob = repo
            .user()
            .add(&mut state.rng(), &state.clock, "bob".to_owned())
            .await
            .unwrap();
        let bob_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &bob, None)
            .await
            .unwrap();

        let issuer = state.url_builder.oidc_issuer().to_string();
        // Alice's sub, but Bob's session id: malformed, must be refused.
        let token = mint_hint(
            &state,
            &issuer,
            &alice.sub,
            Some(&bob_session.id.to_string()),
        );

        let resolved = resolve_id_token_hint(
            &mut repo,
            &state.clock,
            &state.key_store,
            &state.url_builder,
            &token,
        )
        .await
        .unwrap();

        assert!(
            resolved.is_none(),
            "a sid pointing at another user's session must be refused"
        );
    }
}
