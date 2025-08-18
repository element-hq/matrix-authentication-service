# Homeserver configuration

The `matrix-authentication-service` is designed to be run alongside a Matrix homeserver.
It currently only supports [Synapse](https://github.com/element-hq/synapse) version 1.136.0 or later.
The authentication service needs to be able to call the Synapse admin API to provision users through a shared secret, and Synapse needs to be able to call the service to verify access tokens using the OAuth 2.0 token introspection endpoint.

## Configure the connection to the homeserver

In the [`matrix`](../reference/configuration.md#matrix) section of the configuration file, add the following properties:

 - `kind`: the type of homeserver to connect to, currently only `synapse` is supported
 - `homeserver`: corresponds to the `server_name` in the Synapse configuration file
 - `secret`: a shared secret the service will use to call the homeserver MAS API
 - `endpoint`: the URL to which the homeserver is accessible from the service

```yaml
matrix:
  kind: synapse
  homeserver: example.com
  endpoint: "http://localhost:8008"
  secret: "AVeryRandomSecretPleaseUseSomethingSecure"
  # Alternatively, using a file:
  #secret_path: /path/to/secret.txt
```

## Configure the homeserver to delegate authentication to the service

Set up the delegated authentication feature **in the Synapse configuration** in the `matrix_authentication_service` section:

```yaml
matrix_authentication_service:
  enabled: true
  endpoint: http://localhost:8080/
  secret: "AVeryRandomSecretPleaseUseSomethingSecure"
  # Alternatively, using a file:
  #secret_file: /path/to/secret.txt
```

The `endpoint` property should be set to the URL of the authentication service.
This can be an internal URL, to avoid unnecessary round-trips.

The `secret` property must match in both the Synapse configuration and the Matrix Authentication Service configuration.

## Set up the compatibility layer

The service exposes a compatibility layer to allow legacy clients to authenticate using the service.
This works by exposing a few Matrix endpoints that should be proxied to the service.

The following Matrix Client-Server API endpoints need to be handled by the authentication service:

 - [`/_matrix/client/*/login`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3login)
 - [`/_matrix/client/*/logout`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3logout)
 - [`/_matrix/client/*/refresh`](https://spec.matrix.org/latest/client-server-api/#post_matrixclientv3refresh)

See the [reverse proxy configuration](./reverse-proxy.md) guide for more information.


## Migrating from the experimental MSC3861 feature

If you are migrating from the experimental MSC3861 feature in Synapse, you will need to migrate the `experimental_features.msc3861` section of the Synapse configuration to the `matrix_authentication_service` section.

To do so, you need to:

 - Remove the `experimental_features.msc3861` section from the Synapse configuration
 - Add the `matrix_authentication_service` section to the Synapse configuration with:
   - `enabled: true`
   - `endpoint` set to the URL of the authentication service
   - `secret` set to the same secret as the `admin_token` that was set in the `msc3861` section
 - Optionally, remove the client provisionned for Synapse in the `clients` section of the MAS configuration
