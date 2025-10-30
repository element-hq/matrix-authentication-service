# Authorization and sessions

The main job of the authentication service is to grant access to resources to clients, and to let resources know who is accessing them.
In less abstract terms, this means that the service is responsible for issuing access tokens and letting the homeserver (and other services) introspect those access tokens.

## How access tokens work

In MAS, the access token is an opaque string for which the service has metadata associated with it.
An access token has:

- a subject, which is the user the token is issued for
- a list of [scopes](../reference/scopes.md)
- a client for which the token is issued
- a timeframe for which the token is valid

On a single token, metadata is immutable: it doesn't change over time.
One exception is the validity of the token: the service may revoke a token before its expiration date.

A typical client will get a short-lived access token (valid 5 minutes) along with a refresh token.
The refresh token can then be used to get a new access token without the user having to re-authenticate.

## How Synapse behaves

When an incoming request is made to Synapse, it will introspect the access token through the Matrix Authentication Service.
This is using a standard OAuth 2.0 introspection request ([RFC 7662]).

Out of this request, Synapse will care about the following:

- the `active` field, which tells if the token is valid or not
- the `sub` field, which tells which user the token is issued for. This is an opaque string, and Synapse saves the mapping between the Matrix user ID and the subject of the token in its own database
- in case Synapse doesn't know the presented subject, it will look at the `username` field, which it will use as the localpart for the user as fallback
- the `scope` field, which tells which scopes are granted to the token. More specifically, it will look for the following scopes:
  - [`urn:matrix:org.matrix.msc2967.client:api:*`], which grants broad access to the whole Matrix C-S API
  - [`urn:matrix:org.matrix.msc2967.client:device:AABBCC`], which encodes the Matrix device ID used by the client
  - [`urn:synapse:admin:*`], which grants access to the Synapse admin API

It's important to understand that when Synapse delegates authentication to MAS, Synapse no longer manages many user attributes.
This includes the user admin, locked, and deactivated status.

## Compatibility sessions

In addition to OAuth 2.0 sessions, for which we'll go into more details later, MAS also supports the legacy [`/_matrix/client/v3/login`](https://spec.matrix.org/v1.10/client-server-api/#get_matrixclientv3login) API.
This exists as a compatibility layer for clients that don't yet support OAuth 2.0, but has some restrictions compared to the way those sessions behaved in Synapse.

When a client presents a compatibility access token to Synapse, MAS will make it look like to Synapse as if the token had the following scopes:

- [`urn:matrix:org.matrix.msc2967.client:api:*`]
- [`urn:matrix:org.matrix.msc2967.client:device:AABBCC`]

Which corresponds to the broad access to the Matrix C-S API and the device ID of the client, as one would expect from the legacy login API.
One important missing scope is [`urn:synapse:admin:*`], which means that the client won't have access to the Synapse admin API.

This is the case even if the user has the `can_request_admin` attribute set to `true`, and this is by design:
the legacy login API doesn't have a way to request specific scopes, and we don't want to grant admin access to all clients that have a compatibility session.
This was the case in the past with Synapse, as the admin status was set on the user itself, but this is not the case anymore with MAS.

## OAuth 2.0 sessions

Modern clients are expected to use OAuth 2.0 to authenticate with the homeserver.
In OAuth 2.0/OIDC, there are multiple ways to start an OAuth 2.0 session called grants.

An OAuth 2.0 session has three important properties:

- the client, which is the application accessing the resource
- the user, which is the user for which the client is accessing the resource
- a set of scopes, which are the permission granted to the client

There are two main ways to create a client in MAS:

- through the OAuth 2.0 Dynamic Client Registration Protocol ([RFC 7591])
- statically defined [in the configuration file](../reference/configuration.md#clients)

### Authorized as a user or authorized as a client

OAuth 2.0 has an interesting concept where a session can be authorized not just as a user, but also as a client.
This means an OAuth 2.0 session can be created without a user, and only with a client.
It is useful for automated machine-to-machine communication, and is often referred to as "service accounts".

Synapse doesn't yet support this concept, and as such requesting any Synapse API, even the admin API, requires a user attached to the session.

This isn't the case with MAS' GraphQL API, which can be accessed with a client-only session:
the API can be requested by a session which has the [`urn:mas:graphql:*`] and the [`urn:mas:admin`] scope without being backed by a user.

### Supported authorization grants

MAS supports a few different authorization grants for OAuth 2.0 sessions.
Whilst this section won't go into the technical details of how those grants work, it's important to understand what they are and what they are used for.

| Grant type                                          | Entity | User interaction | Matrix C-S API | Synapse Admin API | MAS Admin API | MAS Internal GraphQL API |
| --------------------------------------------------- | ------ | ---------------- | -------------- | ----------------- | ------------- | ------------------------ |
| [Authorization code](#authorization-code-grant)     | User   | Same device      | Yes            | Yes               | Yes           | Yes                      |
| [Device authorization](#device-authorization-grant) | User   | Other device     | Yes            | Yes               | Yes           | Yes                      |
| [Client credentials](#client-credentials-grant)     | Client | None             | No             | No[^admin]        | Yes           | Yes                      |

[^admin]: The Synapse admin API doesn't strictly require a user, but Synapse doesn't support client-only sessions yet. In the future, it will be possible to leverage the client credentials grant to access the Synapse admin API.

#### Authorization code grant

The authorization code grant ([RFC 6749] section 4.1) is used to interactively log in the user on the same device as the client.
This is the most common grant for most Matrix clients and is targeted at human end users.

The general idea is that the client (after registering itself) crafts an authorization URL that the user will visit in their web browser.
The authentication service does whatever it needs to do to authenticate the user, and once the user is authenticated and consented to the access request, the service redirects the user back to the client with an authorization code.
The client then exchanges this authorization code for an access token and a refresh token.

This grant is not meant for automation: it requires user interaction on the same device as where the client lives.

#### Device authorization grant

The device authorization grant ([RFC 8628]) is similar to the authorization code grant, but separates the user interaction from where the client lives.

A classic example of this grant is when a client is on a TV or a game console, where the user wouldn't want to enter their credentials on the device itself.
Instead, the user is shown a code on the device, which they then enter on a different device (like a phone or a computer) to authenticate.

For Matrix, it has two main use cases:

- for CLI tools (or other constrained clients) which can't open a web browser or can't catch a redirect
- for a "login from another existing device" feature, like the "login via QR code" described in [MSC4108]

This grant isn't meant for automation either, as it still requires user interaction.

#### Client credentials grant

The client credentials grant ([RFC 6749] section 4.4) is a bit special, as it lets a client authenticate as itself, without a user.

This has no meaning yet in the Matrix C-S API, but is useful for other APIs like the MAS GraphQL API.
It may also be used in the future as a foundation for a new Application Service API, replacing the current `hs_token`/`as_token` mechanism.

This works by presenting the client credentials to get back an access token.
The simplest type of client credentials is a client ID and client secret pair, but MAS also supports client authentication with a JWT ([RFC 7523]), which is a robust way to authenticate clients without a shared secret.

## Personal sessions (personal access tokens)

Personal access tokens are a credential that can be issued to give access to a user,
with predefined scopes and a predefined expiry time.
Either before or after expiry, the owner of the token can regenerate it, which produces a new
access token with the same scopes but a new expiry time.

Personal access tokens are intended to fulfill two basic use cases:

1. an easy way to obtain a clean token for your own user, for use in automation and scripts;
2. a way to obtain a token for administrative access of another user, either for ad-hoc administrative operations or to set up a bot or similar service.

In the future, users will be able to create their own personal access tokens, but this is currently not implemented
so (1) is currently not supported.

For now, personal access tokens must be created, regenerated and revoked by administrators through the [Admin API], satisfying use case (2).
[Element Admin](https://github.com/element-hq/element-admin), available by default in Element Server Suite, can be used to do this interactively.
You can also use the online beta deployment at [admin-beta.element.dev](https://admin-beta.element.dev/). <!--- TODO stable deployment -->

### Validity

Personal sessions can be used so long as:

- the owner (creator) of the token is still an active and unlocked user (or static OAuth 2 client); and
- the actor (target user, or user being controlled by the token) has not been deactivated. Though the actor is allowed to be locked.


[MSC4108]: https://github.com/matrix-org/matrix-spec-proposals/pull/4108
[RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
[RFC 7523]: https://datatracker.ietf.org/doc/html/rfc7523
[RFC 7591]: https://datatracker.ietf.org/doc/html/rfc7591
[RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662
[RFC 8628]: https://datatracker.ietf.org/doc/html/rfc8628
[`urn:matrix:org.matrix.msc2967.client:api:*`]: ../reference/scopes.md#urnmatrixorgmatrixmsc2967clientapi
[`urn:matrix:org.matrix.msc2967.client:device:AABBCC`]: ../reference/scopes.md#urnmatrixorgmatrixmsc2967clientdevicedevice-id
[`urn:synapse:admin:*`]: ../reference/scopes.md#urnsynapseadmin
[`urn:mas:graphql:*`]: ../reference/scopes.md#urnmasgraphql
[`urn:mas:admin`]: ../reference/scopes.md#urnmasadmin
[Admin API]: ./admin-api.md
