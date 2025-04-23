# Migrating an existing homeserver

One of the design goals of MAS has been to allow it to be used to migrate an existing homeserver, specifically without requiring users to re-authenticate and ensuring that all existing clients continue to work.

Features that support this include:

- Ability to import existing password hashes from Synapse
- Ability to import existing sessions and devices
- Ability to import existing access tokens
- Ability to import existing upstream IdP subject ID mappings
- Provides a compatibility layer for legacy Matrix authentication

## Preparing for the migration

The deployment is non-trivial, so it is important to read through and understand the steps involved and make a plan before starting.

### Is your setup ready to be migrated?

#### SAML2 and LDAP Single Sign-On Providers are not supported

A deployment that requires SAML or LDAP-based authentication should use a service like [Dex](https://github.com/dexidp/dex) to bridge between the SAML provider and the authentication service.
MAS differs from Synapse in that it does **not** have built-in support for SAML or LDAP-based providers.

#### Custom password providers are not supported

If your Synapse homeserver currently uses a custom password provider module, please note that MAS does not support these.

#### SQLite databases are not supported

It is worth noting that MAS currently only supports PostgreSQL as a database backend.
The migration tool only supports reading from PostgreSQL for the Synapse database as well.

### Install and configure MAS alongside your existing homeserver

Follow the instructions in the [installation guide](installation.md) to install MAS alongside your existing homeserver.

You'll need a blank PostgreSQL database for MAS to use; it does not share the database with the homeserver.

MAS provides a tool to generate a configuration file based on your existing Synapse configuration. This is useful for kickstarting your new configuration.

```sh
mas-cli config generate --synapse-config homeserver.yaml --output mas_config.yaml
```

When using this tool, be careful to examine the log output for any warnings about unsupported configuration options.

#### Local passwords

Synapse uses bcrypt as its password hashing scheme, while MAS defaults to using the newer argon2id.
You will have to configure the version 1 scheme as bcrypt for migrated passwords to work.
It is also recommended that you keep argon2id as version 2 so that once users log in, their hashes will be updated to the newer, recommended scheme.

Example passwords configuration:
```yml
passwords:
  enabled: true
  schemes:
  - version: 1
    algorithm: bcrypt
    # Optional, must match the `password_config.pepper` in the Synapse config
    #secret: secretPepperValue
  - version: 2
    algorithm: argon2id
```

If you have a pepper configured in your Synapse password configuration, you'll need to match that on version 1 of the equivalent MAS configuration.

The migration checker will inform you if this has not been configured properly.

### Map any upstream SSO providers

If you are using an upstream SSO provider, then you will need to configure the upstream provider in MAS manually.

MAS does not support SAML or LDAP upstream providers.
If you are using one of these, you will need to use an adapter such as Dex at this time, but we have not yet documented this procedure.

Each upstream provider that was used by at least one user in Synapse will need to be configured in MAS.

Set the `synapse_idp_id` attribute on the provider to:

- `"oidc"` if you used an OIDC provider in Synapse's legacy `oidc_config` configuration section.
- `"oidc-myprovider"` if you used an OIDC provider in Synapse's `oidc_providers` configuration list, with a `provider` of `"myprovider"`.
  (This is because Synapse prefixes the provider ID with `oidc-` internally.)

Without the `synapse_idp_id`s being set, `mas-cli syn2mas` does not understand which providers in Synapse correspond to which provider in MAS.

For example, if your Synapse configuration looked like this:

```yaml
oidc_providers:
  - idp_id: dex
    idp_name: "My Dex server"
    issuer: "https://example.com/dex"
    client_id: "synapse"
    client_secret: "supersecret"
    scopes: ["openid", "profile", "email"]
    user_mapping_provider:
      config:
        localpart_template: "{{ user.email.split('@')[0].lower() }}"
        email_template: "{{ user.email }}"
        display_name_template: "{{ user.name|capitalize }}"
```

Then the equivalent configuration in MAS would look like this:

```yaml
upstream_oauth2:
  providers:
  - id: 01JSHPZHAXC50QBKH67MH33TNF
    synapse_idp_id: oidc-dex
    issuer: "https://example.com/dex"
    human_name: "My Dex server"
    client_id: "synapse"
    client_secret: "supersecret"
    token_endpoint_auth_method: client_secret_basic
    scope: "email openid profile"
    claims_imports:
      localpart:
        action: require
        template: "{{ user.email.split('@')[0].lower() }}"
      displayname:
        action: force
        template: "{{ user.name|capitalize }}"
      email:
        action: force
        template: "{{ user.email }}"
```

The migration checker will inform you if a provider is missing from MAS' config.

### Run the migration checker

You can use the `check` command of the `syn2mas` tool to identify configuration problems before starting the migration.
You do not need to stop Synapse to run this command.

```sh
mas-cli syn2mas check --config mas_config.yaml --synapse-config homeserver.yaml
```

This will output a list of errors and warnings, or tell you that the check completed with no errors or warnings.

If you have any errors, you must resolve them before starting the migration.

If you have any warnings, please read and understand them, and possibly resolve them.
Resolving warnings is not strictly required before starting the migration.

### Do a dry-run of the import to test

MAS can perform a dry-run of the import, which is safe to run without stopping Synapse.
It will perform a full data migration but then empty the MAS database at the end to roll back.

This means it is safe to run multiple times without worrying about resetting the MAS database.
It also means the time this dry-run takes is representative of the time it will take to perform the actual migration.

```sh
mas-cli syn2mas migrate --config mas_config.yaml --synapse-config homeserver.yaml --dry-run
```

## Doing the migration

Having completed the preparation, you can now proceed with the actual migration. Note that this will require downtime for the homeserver and is not easily reversible.

### Backup your data and configuration

As with any migration, it is important to back up your data before proceeding.

We also suggest making a backup copy of your homeserver's known good configuration before making any changes to enable MAS integration.

### Shut down the homeserver

This ensures that no new sessions are created while the migration is in progress.

### Configure the homeserver to enable MAS integration

Follow the instructions in the [homeserver configuration guide](homeserver.md) to configure the homeserver to use MAS.

### Do the import

Once the homeserver has been stopped, MAS has been configured (but is not running!), and you have a successful migration check, run `syn2mas`'s `migrate` command.

```sh
mas-cli syn2mas migrate --config mas_config.yaml --synapse-config homeserver.yaml
```

#### What to do if it goes wrong

If the migration fails with an error:

- You can try to fix the error and make another attempt by re-running the command; or
- You can revert your homeserver configuration (so MAS integration is disabled once more) and abort the migration for now. In this case, you should not start MAS up.

In *some cases*, MAS may have written to its own database during a failed migration, causing it to complain in subsequent runs.
In this case, you can safely delete and recreate the MAS database, then start over.

In *any case*, the migration tool itself **will not** write to the Synapse database, so as long as MAS hasn't been started, it is safe to roll back the migration without restoring the Synapse database.

Please report migration failures to the developers.

### Start up the homeserver

Start up the homeserver again with the new configuration.

### Start up MAS

Start up MAS.

### Update or serve the .well-known

The `.well-known/matrix/client` needs to be served as described [here](./well-known.md).
