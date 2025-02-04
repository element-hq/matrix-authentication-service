# Homeserver configuration

The `matrix-authentication-service` is designed to be run alongside a Matrix homeserver.
It currently only supports [Synapse](https://github.com/element-hq/synapse) through the experimental OAuth delegation feature.
The authentication service needs to be able to call the Synapse admin API to provision users through a shared secret, and Synapse needs to be able to call the service to verify access tokens using the OAuth 2.0 token introspection endpoint.

## Provision a client for the Homeserver to use

In the [`clients`](../reference/configuration.md#clients) section of the configuration file, add a new client with the following properties:

 - `client_id`: a unique identifier for the client. It must be a valid [ULID](https://github.com/ulid/spec), and it happens that `0000000000000000000SYNAPSE` is a valid ULID.
 - `client_auth_method`: set to `client_secret_basic`. Other methods are possible, but this is the easiest to set up.
 - `client_secret`: a shared secret used for the homeserver to authenticate

```yaml
clients:
  - client_id: 0000000000000000000SYNAPSE
    client_auth_method: client_secret_basic
    client_secret: "SomeRandomSecret"
```

**Don't forget to sync the configuration file** with the database after adding the client, using the [`config sync`](../reference/cli/config.md#config-sync---prune---dry-run) command.

## Configure the connection to the homeserver

In the [`matrix`](../reference/configuration.md#matrix) section of the configuration file, add the following properties:

 - `homeserver`: corresponds to the `server_name` in the Synapse configuration file
 - `secret`: a shared secret the service will use to call the homeserver admin API
 - `endpoint`: the URL to which the homeserver is accessible from the service

```yaml
matrix:
  homeserver: localhost:8008
  secret: "AnotherRandomSecret"
  endpoint: "http://localhost:8008"
```

## Configure the homeserver to delegate authentication to the service

Set up the delegated authentication feature in the Synapse configuration in the `experimental_features` section:

```yaml
experimental_features:
  msc3861:
    enabled: true

    # Synapse will call `{issuer}/.well-known/openid-configuration` to get the OIDC configuration
    issuer: http://localhost:8080/

    # Matches the `client_id` in the auth service config
    client_id: 0000000000000000000SYNAPSE
    # Matches the `client_auth_method` in the auth service config
    client_auth_method: client_secret_basic
    # Matches the `client_secret` in the auth service config
    client_secret: "SomeRandomSecret"

    # Matches the `matrix.secret` in the auth service config
    admin_token: "AnotherRandomSecret"

    # URL to advertise to clients where users can self-manage their account
    # Defaults to the URL advertised by MAS, e.g. `https://{public_mas_domain}/account/`
    #account_management_url: "http://localhost:8080/account/"

    # URL which Synapse will use to introspect access tokens
    # Defaults to the URL advertised by MAS, e.g. `https://{public_mas_domain}/oauth2/introspect`
    # This is useful to override if Synapse has a way to call the auth service's
    # introspection endpoint directly, skipping intermediate reverse proxies
    #introspection_endpoint: "http://localhost:8080/oauth2/introspect"
```

## Set up the compatibility layer

The service exposes a compatibility layer to allow legacy clients to authenticate using the service.
This works by exposing a few Matrix endpoints that should be proxied to the service.

The following Matrix Client-Server API endpoints need to be handled by the authentication service:

 - [`/_matrix/client/*/login`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3login)
 - [`/_matrix/client/*/logout`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3logout)
 - [`/_matrix/client/*/refresh`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3refresh)

See the [reverse proxy configuration](./reverse-proxy.md) guide for more information.
