# Homeserver configuration

The `matrix-authentication-service` is designed to be run alongside a Matrix homeserver.
It currently only supports [Synapse](https://github.com/element-hq/synapse) through the experimental OAuth delegation feature.
The authentication service needs to be able to call the Synapse admin API to provision users through a shared secret, and Synapse needs to be able to call the service to verify access tokens using the OAuth 2.0 token introspection endpoint.

> Note: This documentation applies to Synapse v1.136.0 and higher. For older Synapse versions, refer to docs for [v0.16](https://github.com/element-hq/matrix-authentication-service/blob/release/v0.20/docs/setup/homeserver.md)

## Configure the connection to the homeserver

In the [`matrix`](../reference/configuration.md#matrix) section of the configuration file, add the following properties:

 - `homeserver`: corresponds to the `server_name` in the Synapse configuration file
 - `secret`: a shared secret the service will use to call the homeserver admin API
 - `endpoint`: the URL to which the homeserver is accessible from the service

```yaml
matrix:
  homeserver: localhost:8008
  secret: "SomeRandomSecret"
  endpoint: "http://localhost:8008"
```

**Don't forget to sync the configuration file** with the database after configuring homeserver connection, using the [`config sync`](../reference/cli/config.md#config-sync---prune---dry-run) command.

## Configure the homeserver to delegate authentication to the service

Set up the delegated authentication feature in the Synapse configuration:

```yaml
matrix_authentication_service:
  # Enable the MAS integration
  enabled: true
  # The base URL where Synapse will contact MAS
  endpoint: http://localhost:8080
  # The shared secret used to authenticate MAS requests, must be the same as `matrix.secret` in the MAS configuration
  # See https://element-hq.github.io/matrix-authentication-service/reference/configuration.html#matrix
  secret: "SomeRandomSecret"
```

## Optional: Enable QR code login

To enable QR code login you need to enable MSC 4108 in the Synapse configuration in the `experimental_features` section:

```yaml
experimental_features:
  msc4108_enabled: true
```

> Note: There is a [known bug](https://github.com/element-hq/synapse/issues/18808) that prevents enabling MSC 4108 in Synapse v1.136.0 when MAS is configured as described above. Either use the [older method of configuring MAS on Synapse](https://github.com/element-hq/matrix-authentication-service/blob/release/v0.20/docs/setup/homeserver.md), or upgrade to v1.137.0

## Set up the compatibility layer

The service exposes a compatibility layer to allow legacy clients to authenticate using the service.
This works by exposing a few Matrix endpoints that should be proxied to the service.

The following Matrix Client-Server API endpoints need to be handled by the authentication service:

 - [`/_matrix/client/*/login`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3login)
 - [`/_matrix/client/*/logout`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3logout)
 - [`/_matrix/client/*/refresh`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3refresh)

See the [reverse proxy configuration](./reverse-proxy.md) guide for more information.
