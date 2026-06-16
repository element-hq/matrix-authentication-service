# Data retention

This page describes what information MAS stores about users, sessions and authentication attempts, how long it is kept, and what happens to it when a user deactivates their account.

It is intended for administrators who need to answer questions about data handling — for example to populate a privacy policy, respond to data-subject requests, or evaluate MAS for a regulated deployment.

This document only covers data that MAS stores itself, in its own PostgreSQL database. The Matrix homeserver MAS is paired with stores its own data (rooms, messages, devices, …), which is out of scope here. Logs, traces and metrics exported to external systems (e.g. via OpenTelemetry or Sentry) are also out of scope; their retention is controlled by whoever operates those systems.

## What MAS stores about a user

When a user has an active account, MAS keeps the following records.

### Account

- The username (Matrix localpart).
- The timestamp the account was created.
- The deactivation and locking timestamps, if applicable.
- A flag indicating whether the user is allowed to request the admin scope when authenticating.

### Email addresses

- One or more email addresses associated with the account, along with the timestamp each address was added and the timestamp it was confirmed (if it has been).

The account self-service UI lets the user list, add and remove their own email addresses.

### Passwords

If local password authentication is enabled:

- The current password hash.
- The hashes of every previous password the account has ever used. MAS does not use these to prevent password reuse; they simply accumulate because old rows are never deleted when a password is changed.

Only hashes are stored — plaintext passwords are never persisted.

### Upstream SSO links

If the user authenticates through an upstream identity provider (Google, Microsoft, Keycloak, Dex, …), MAS records, for each provider the user has used:

- The upstream provider's identifier for the user (the OIDC `sub` claim, sometimes called the "Google ID", "Microsoft ID", etc.).
- A human-readable label (typically the email or username from the upstream provider) shown in administrative tooling.
- The timestamp the link was created.

These links are not currently visible to the user themselves; they can be inspected by an administrator via the Admin API.

### Unsupported third-party identifiers

For accounts imported from Synapse with `syn2mas`, MAS may carry over third-party identifiers that MAS itself does not handle (most commonly phone numbers / MSISDNs). These are stored only so that the homeserver can keep using them; MAS does not perform any authentication against them.

## What MAS stores about each session

Every time a user authenticates, MAS creates one or more session records. There are several types:

- **Browser sessions** — the cookie-backed sessions used to interact with MAS itself (the account UI, the consent screen, etc.).
- **OAuth 2.0 sessions** — created when a Matrix client (e.g. Element) logs in via the OAuth 2.0 / OIDC flow. There is one such session per logged-in client.
- **Compatibility sessions** — the equivalent for clients still using the legacy Matrix `/login` API.
- **Personal access token sessions** — long-lived sessions backing personal access tokens. The token acts on behalf of a user and is owned either by that user or by an OAuth 2.0 client. Note that personal access tokens are not yet user-serviced, see [#4492](https://github.com/element-hq/matrix-authentication-service/issues/4492).
- **Upstream OAuth authorisation sessions** — created when MAS authenticates a user against an upstream identity provider. See [Upstream OAuth sessions](#upstream-oauth-sessions) below for the data they store, which is somewhat different.

For each browser, OAuth 2.0, compatibility or personal-access-token session, MAS records:

- When it was created.
- When it was finished (logged out, revoked, or expired), if applicable.
- The last time it was seen active.
- The IP address it was last seen from.
- The User-Agent string seen when it was created.
- For OAuth 2.0 and compatibility sessions, which OAuth 2.0 client (i.e. which Matrix client) the session belongs to.
- A user-set human-readable name, if the user has named the device.

Active sessions, their device names, last-seen IPs and parsed User-Agent information are surfaced to the user in the "Sessions" page of the account self-service UI, so they can review and revoke their active sessions.

### Tokens

OAuth 2.0 and compatibility sessions are backed by access tokens, and OAuth 2.0 sessions additionally by refresh tokens. Personal access token sessions are backed by long-lived tokens of which only a SHA-256 hash is stored. Token retention is described in [Retention periods](#retention-periods) below.

### Upstream OAuth sessions

When MAS redirects a user to an upstream identity provider to authenticate, it creates an upstream authorisation session row. In addition to the OAuth/OIDC state needed to complete the flow, MAS stores, once the authorisation completes:

- The raw ID Token returned by the upstream provider (a JWT).
- A decoded copy of the ID Token's claims, used to match incoming back-channel logout notifications against the right session.

The claims an ID Token contains depend entirely on the upstream provider and which scopes MAS requested from it — typically a subject identifier, often an email address, sometimes a name. This data is associated with the corresponding local user session for as long as that session is retained.

## What MAS stores about authentication attempts

Beyond completed sessions, MAS keeps a small amount of state about authentication and account-recovery flows in progress:

- **User registrations** — the record of a registration attempt, whether completed or not. This includes the IP address and User-Agent of the request, the username and display name requested, the URL of the terms-of-service version accepted, a reference to the email-authentication session used, and the hashed password if one was set. It is retained briefly to help investigate abuse such as automated bulk registration.
- **OAuth 2.0 authorisation grants** and **device-code grants** — short-lived rows tracking an in-flight authorisation request between a client and MAS.
- **Email authentication codes** and **account-recovery sessions** — short-lived rows tracking "send me a code" and "I forgot my password" flows. The codes themselves expire within 10 minutes; the surrounding records are kept slightly longer for diagnostics.

## Retention periods

Most rows in the database are first *soft-deleted* — marked as finished, revoked or consumed — and then hard-deleted by scheduled cleanup jobs after a delay. The delay supports protocol features (e.g. idempotent token introspection and revocation), lets administrators investigate recent incidents, and gives operational tooling a short window in which finished sessions are still inspectable.

| Data | Retention | Notes |
| --- | --- | --- |
| Last-seen IP address on a session | Cleared 30 days after last activity | Wiped even if the session is still active |
| Finished browser, OAuth 2.0 and compatibility sessions | 30 days after they finish | Then hard-deleted along with their tokens |
| User registrations (incl. IP and User-Agent) | 30 days | Retained to investigate abusive registration patterns |
| Revoked or consumed OAuth 2.0 access / refresh tokens | 1 hour | Kept briefly so revocation and refresh flows remain idempotent |
| Expired OAuth 2.0 access tokens | 30 days | Supports idempotent introspection of recently-expired tokens |
| OAuth 2.0 authorisation grants and device-code grants | 7 days | In-flight grants for completed or abandoned login attempts |
| Email authentication codes and account-recovery sessions | 7 days | The one-time codes themselves expire within 10 minutes |
| Upstream OAuth authorisation sessions, once their local user session is gone | 7 days | Linked upstream sessions are otherwise kept for as long as the local user session they're attached to |
| Upstream OAuth links not associated to a user | 7 days | Created during an upstream login that was never completed |
| Internal background-job records | 30 days | Kept for debugging; may contain user data like display names or email addresses |

The exact delays are chosen for engineering and operational reasons (audit visibility, idempotency, abuse investigation) and are not currently configurable. Most cleanup jobs run hourly, spread across the hour to even out database load; a few (expired-token cleanup, inactive-session expiration) run on different schedules.

### Optional: inactive session expiration

MAS experimentally supports automatically finishing sessions that have been inactive for a configurable period. This is *off by default* and can be enabled per session type — browser, OAuth 2.0, or compatibility — under `experimental.inactive_session_expiration` in the configuration file. Once a session is finished by this mechanism, it then follows the normal 30-day retention rule above.

## What happens when an account is deactivated

When a user deactivates their account (either themselves from the account UI, or via the Admin API), MAS:

1. Marks the account as deactivated, preventing any further login.
2. Immediately finishes every active session belonging to the user — browser, OAuth 2.0 and compatibility — and revokes every personal access token whose actor or owner is that user.
3. Deletes every email address attached to the account.
4. Deletes any unsupported third-party identifiers (e.g. imported phone numbers).
5. Calls the homeserver to deactivate the user there as well. If "erasure" was requested, the homeserver is also asked to redact the user's content per its own policy.

The sessions finished in step 2 then follow the same 30-day retention as any other finished session — the rows are kept for that period and the last-seen IPs are wiped after 30 days of inactivity (which, since the sessions are now finished, will happen 30 days after deactivation at the latest).

### Known limitations

The following pieces of information are **not** removed by deactivation today. Closing these gaps is tracked work; this section will be updated as the behaviour changes.

- **Password hash history** — the row(s) in `user_passwords` are kept.
- **Upstream SSO links** — the mapping between the local account and any upstream provider subject ID is kept.
- **Upstream OAuth ID tokens and claims** — these are tied to the user sessions that referenced them. As long as those user sessions are retained (30 days after they finish), the associated ID token claims are too.
- **The user record itself** — the username and the timestamps of creation, deactivation and lock are kept so the account cannot be silently re-registered and so administrators retain an audit trail.

## Logs, traces and metrics

MAS emits structured logs, OpenTelemetry traces and Prometheus / OpenTelemetry metrics. Depending on log level and instrumentation, these can contain IP addresses, User-Agents, usernames and request identifiers. They are sent to whichever sink the operator has configured (stdout, an OTLP collector, Sentry, …) and their retention is governed entirely by that downstream system — MAS does not retain its own copy.
