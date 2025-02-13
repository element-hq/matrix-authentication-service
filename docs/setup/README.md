# Planning the installation

This part of the documentation goes through installing the service, the important parts of the configuration file, and how to run the service.

Before going through the installation, it is important to understand the different components of an OIDC-native Matrix homeserver, and how they interact with each other.
It is meant to complement the homeserver, replacing the internal authentication mechanism with the authentication service.

Making a homeserver deployment OIDC-native radically shifts the authentication model: the homeserver is no longer responsible for managing user accounts and sessions.
The authentication service becomes the source of truth for user accounts and access tokens, and the homeserver only verifies the validity of the tokens it receives through the service.

At time of writing, the authentication service is meant to be run on a standalone domain name (e.g. `auth.example.com`), and the homeserver on another (e.g. `matrix.example.com`).
This domain will be user-facing as part of the authentication flow.

When a client initiates an authentication flow, it will discover the authentication service through the deployment `.well-known/matrix/client` endpoint.
This file will refer to an `issuer`, which is the canonical name of the authentication service instance.
Out of that issuer, it will discover the rest of the endpoints by calling the `[issuer]/.well-known/openid-configuration` endpoint.
By default, the `issuer` will match the root domain where the service is deployed (e.g. `https://auth.example.com/`), but it can be configured to be different.

An example setup could look like this:

  - The deployment domain is `example.com`, so Matrix IDs look like `@user:example.com`
  - The issuer chosen is `https://auth.example.com/`
  - The homeserver is deployed on `matrix.example.com`
  - The authentication service is deployed on `auth.example.com`
  - Calling `https://example.com/.well-known/matrix/client` returns the following JSON:

    ```json
    {
      "m.homeserver": {
        "base_url": "https://matrix.example.com"
      },
      "org.matrix.msc2965.authentication": {
        "issuer": "https://auth.example.com/",
        "account": "https://auth.example.com/account"
      }
    }
    ```
    
  - Calling `https://auth.example.com/.well-known/openid-configuration` returns a JSON document similar to the following:

    ```json
    {
        "issuer": "https://auth.example.com/",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/oauth2/token",
        "jwks_uri": "https://auth.example.com/oauth2/keys.json",
        "registration_endpoint": "https://auth.example.com/oauth2/registration",
        "//": "..."
    }
    ```

With the installation planned, it is time to go through the installation and configuration process.
The first section focuses on [installing the service](./installation.md).
