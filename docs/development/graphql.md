# Internal GraphQL API

> **Note:** This API used to be the way for external tools to interact with MAS. However, **external usage is now deprecated** in favour of the REST based [Admin API](../topics/admin-api.md). External access to this API will be removed in a future release.

MAS uses an internal GraphQL API which is used by the self-service user interface (usually accessible on `/account/`), for users to manage their own account.

The endpoint for this API can be discovered through the OpenID Connect discovery document, under the `org.matrix.matrix-authentication-service.graphql_endpoint` key.
Though it is usually hosted at `https://<mas-host>/graphql`.

GraphQL uses [a self-describing schema](https://github.com/element-hq/matrix-authentication-service/blob/main/frontend/schema.graphql), which means that the API can be explored in tools like the GraphQL Playground.
If enabled, MAS hosts an instance of the playground at `https://<mas-host>/graphql/playground`.

## Authorization

There are two ways to authorize a request to the GraphQL API:

 - if you are requesting from the self-service user interface (or the MAS-hosted GraphQL Playground), it will use the session cookies to authorize as the current user. This mode only allows the user to access their own data, and will never provide admin access.
 - else you will need to provide an OAuth 2.0 access token in the `Authorization` header, with the `Bearer` scheme.

The access token must have the [`urn:mas:graphql:*`] scope to be able to access the GraphQL API.
With only this scope, the session will be authorized as the user who owns the access token, and will only be able to access their own data.

To get full access to the GraphQL API, the access token must have the [`urn:mas:admin`] scope in addition to the [`urn:mas:graphql:*`] scope.

[`urn:mas:graphql:*`]: ../reference/scopes.md#urnmasgraphql
[`urn:mas:admin`]: ../reference/scopes.md#urnmasadmin
