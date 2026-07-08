# Request log format

For every HTTP request it serves, the service emits a single structured log
line once the response is ready. These lines are emitted on the
`http.server.response` [tracing] event, at a level derived from the response
status code:

- `INFO` for `1xx`–`3xx` responses,
- `WARN` for `4xx` responses,
- `ERROR` for `5xx` responses.

They are designed to be ingested by log analysis systems, to keep an audit trail
and to classify activity such as logins, logouts and token issuance.
Combined with the [`client.address`](#fields) and [`requester`](#fields) fields,
each request can be attributed to a client IP and to the user or client that
made it.

## Example

```
2026-06-17T10:49:22.419912Z  INFO http.server.response POST-71 - "POST /login HTTP/2.0" 303 See Other "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15" [polls: 12, cpu: 4.7ms, db: 10.9ms, elapsed: 46.9ms, queries: 4, fetched: 2] requester=user:01H8VZ…(alice) client.address=2a01:e0a:f5c:5b02:85c9:3849:4811:4383 trace.id=c8c8fc32288a76693e028ee97a6030a0
```

Broken down:

| Part | Example | Meaning |
| --- | --- | --- |
| Timestamp | `2026-06-17T10:49:22.419912Z` | When the line was logged (response time), in UTC. |
| Level | `INFO` | Log level, derived from the status code (see above). |
| Event | `http.server.response` | The event name; filter on this to select request logs. |
| Request id | `POST-71` | The request method followed by a process-unique counter. Every log line emitted while handling the same request shares this id, so it can be used to correlate them. |
| Request line | `"POST /login HTTP/2.0"` | The HTTP method, path and protocol version. The path does **not** include the query string. |
| Status | `303 See Other` | The response status code and its reason phrase. |
| User agent | `"Mozilla/5.0 …"` | The `User-Agent` header, or `"-"` if absent. |
| Stats | `[polls: 12, …]` | Log context statistics, see below. |

## Log context statistics

Each request log line includes statistics about the request task in brackets,
such as the number of polls, CPU time used, and wall-clock time elapsed.

| Field | Example | Meaning |
| --- | --- | --- |
| `polls` | `12` | The number of times the request task was polled. |
| `cpu` | `0.5ms` | The CPU time used by the request task, in milliseconds. |
| `db` | `0.3ms` | The time spent querying the database, in milliseconds. |
| `elapsed` | `1.2ms` | The wall-clock time elapsed handling the request, in milliseconds. |
| `queries` | `3` | The number of database queries executed. |
| `fetched` | `2` | The number of rows fetched from the database. |

## Fields

The following structured fields are appended to the line. Several are only
present when applicable, so a missing field is meaningful in itself.

| Field | Example | Meaning |
| --- | --- | --- |
| `requester` | `user:01H8VZ…(alice)` | Who the request is attributed to. One of `user:<id>(<username>)`, `user:<id>` (when the username isn't loaded), `oauth2-client:<id>`, or `homeserver`. **Absent** for unauthenticated requests (e.g. a login page before logging in). |
| `client.address` | `2a01:e0a:…` | The client IP address ([OpenTelemetry `client.address`][otel-client]), inferred from the connection and the trusted proxy configuration. **Absent** if it couldn't be determined. |
| `graphql.operation.type` | `query` | For `/graphql` requests only: the type of the executed operation, one of `query`, `mutation` or `subscription`. |
| `graphql.operation.name` | `CurrentUserGreeting` | For `/graphql` requests only: the name of the executed operation, when the query document names it. |
| `trace.id` | `c8c8fc32…` | The OpenTelemetry trace id, to correlate the line with a distributed trace. |

> `requester` reflects who the request _acted as_. For a token request it is the
> OAuth 2.0 client, not the end user the token is for; for the introspection
> endpoint it is the calling client or the homeserver, not the token's subject.

## Classifying activity

Most activity can be classified from the **method**, **path** and **status**,
with the `requester` field telling you who performed it. A `303 See Other`
typically means the action succeeded and the browser is being redirected, while
a `200 OK` on a form-submitting endpoint usually means the form was
re-rendered with an error.

| Activity | Request | Success looks like |
| --- | --- | --- |
| Browser login | `POST /login` | `303 See Other` with a `requester` (a `200 OK` re-renders the form, e.g. on a wrong password) |
| Browser logout | `POST /logout` | `303 See Other` with the `requester` being the user that was logged out |
| Registration | `GET /register/steps/…/finish` | `303 See Other` with the newly-created user as `requester` |
| Login via an upstream provider | `POST /upstream/link/…` | `303 See Other` with a `requester` |
| Matrix client login (compatibility layer) | `POST /_matrix/client/*/login` | `200 OK` with a `requester` |
| Matrix client logout | `POST /_matrix/client/*/logout` (and `/logout/all`) | `200 OK` |
| Token issuance | `POST /oauth2/token` | `200 OK` with an `oauth2-client:` `requester` |
| Token revocation | `POST /oauth2/revoke` | `200 OK` with an `oauth2-client:` `requester` |
| Token introspection | `POST /oauth2/introspect` | `200 OK`, `requester` is the calling client or `homeserver` |
| Authorization grant | `GET`/`POST /authorize` | a `303 See Other` once the user consents |
| Account self-service action | `POST /graphql` | `200 OK`; the actual activity is in `graphql.operation.name` (see below) |

### Account self-service operations (GraphQL)

The account management area (served at `/account/`) performs its actions
(adding an email, changing the password, ending a session, and so on) as
GraphQL mutations against `POST /graphql`, authenticated with the user's
session cookie. They are therefore attributed (the `requester` is the signed-in user),
but the path alone can't tell them apart: the activity is identified by
`graphql.operation.name`.

> The HTTP status is almost always `200 OK` for GraphQL, **even when the
> operation fails**: GraphQL reports errors in the response body, not the
> status code. The log line tells you an operation was _attempted_ by a given
> user, not whether it succeeded.

The notable operations sent by the bundled frontend (a custom client may use
different names):

| `graphql.operation.name` | Activity |
| --- | --- |
| `AddEmail` / `DoVerifyEmail` / `RemoveEmail` | Add, verify or remove an email address |
| `ChangePassword` / `RecoverPassword` | Change the password, or reset it via a recovery link |
| `SetDisplayName` | Change the display name |
| `DeactivateUser` | Deactivate the account |
| `AllowCrossSigningReset` | Allow resetting the cross-signing keys |
| `EndBrowserSession` / `EndCompatSession` / `EndOAuth2Session` | Sign out a browser, Matrix-client or OAuth 2.0 session |
| `SetCompatSessionName` / `SetOAuth2SessionName` | Rename a session |

[tracing]: https://docs.rs/tracing/
[otel-client]: https://opentelemetry.io/docs/specs/semconv/attributes-registry/client/
