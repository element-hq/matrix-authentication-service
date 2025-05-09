# Planning the installation

This part of the documentation goes through installing the service, the important parts of the configuration file, and how to run the service.

Before going through the installation, it is important to understand the different components of an OIDC-native Matrix homeserver, and how they interact with each other.
It is meant to complement the homeserver, replacing the internal authentication mechanism with the authentication service.

Making a homeserver deployment OIDC-native radically shifts the authentication model: the homeserver is no longer responsible for managing user accounts and sessions.
The authentication service becomes the source of truth for user accounts and access tokens, and the homeserver only verifies the validity of the tokens it receives through the service.

At time of writing, the authentication service is meant to be run on a standalone domain name (e.g. `auth.example.com`), and the homeserver on another (e.g. `matrix.example.com`).
This domain will be user-facing as part of the authentication flow.

An example setup could look like this:

  - The deployment domain is `example.com`, so Matrix IDs look like `@user:example.com`
  - The authentication service is deployed on `auth.example.com`
  - The homeserver is deployed on `matrix.example.com`

With the installation planned, it is time to go through the installation and configuration process.
The first section focuses on [installing the service](./installation.md).
