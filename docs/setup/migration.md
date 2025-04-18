# Migrating an existing homeserver

One of the design goals of MAS has been to allow it to be used to migrate an existing homeserver to an OIDC-based architecture.

Specifically without requiring users to re-authenticate and that non-OIDC clients continue to work.

Features that are provided to support this include:

- Ability to import existing password hashes from Synapse
- Ability to import existing sessions and devices
- Ability to import existing access tokens linked to devices (ie not including short-lived admin puppeted access tokens)
- Ability to import existing upstream IdP subject ID mappings
- Provides a compatibility layer for legacy Matrix authentication

There will be tools to help with the migration process itself. But these aren't quite ready yet.

## Preparing for the migration

The deployment is non-trivial so it is important to read through and understand the steps involved and make a plan before starting.

### Is your setup ready to be migrated?

#### SAML2 and LDAP Single Sign-On Providers are not supported

A deployment which requires SAML or LDAP-based authentication should use a service like [Dex](https://github.com/dexidp/dex) to bridge between the SAML provider and the authentication service.
MAS is different from Synapse in that it does **not** have built-in support for SAML or LDAP-based providers.

#### Custom password providers are not supported

If your Synapse homeserver currently uses a custom password provider module, please note that MAS does not support these.

#### SQLite databases are not supported

It is worth noting that MAS currently only supports PostgreSQL as a database backend.

### Install and configure MAS alongside your existing homeserver

Follow the instructions in the [installation guide](installation.md) to install MAS alongside your existing homeserver.

You'll need a blank PostgreSQL database for MAS to use; it does not share the database with the homeserver.

Set up a configuration file but don't start MAS, or create any users, yet.

#### Local passwords

Synapse uses bcrypt as its password hashing scheme while MAS defaults to using the newer argon2id.
You will have to configure the version 1 scheme as bcrypt for migrated passwords to work.
It is also recommended that you keep argon2id as version 2 so that once users log in, their hashes will be updated to the newer recommended scheme.
If you have a `pepper` set in the `password_config` section of your Synapse config, then you need to specify this `pepper` as the `secret` field for your `bcrypt` scheme.

Example passwords configuration:
```yml
passwords:
  enabled: true
  schemes:
  - version: 1 # TODO I think v:2 has to come first in this list
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
If you are using one of these, you will need to use an adapter such as Dex at this time,
but we have not yet documented this procedure.

Each upstream provider that was used by at least one user in Synapse will need to be configured in MAS.

Set the `synapse_idp_id` attribute on the provider to:

- `"oidc"` if you used an OIDC provider in Synapse's legacy `oidc_config` configuration section.
- `"oidc-myprovider"` if you used an OIDC provider in Synapse's `oidc_providers` configuration list,
  with a `provider` of `"myprovider"`.
  (This is because Synapse prefixes the provider ID with `oidc-` internally.)

Without the `synapse_idp_id`s being set, syn2mas does not understand which providers
in Synapse correspond to which provider in MAS.

!!!!!!!!! TODO add an example here

The migration checker will inform you if a provider is missing from MAS' config.

### Run the migration checker

You can use the `check` command of the `syn2mas` tool to identify configuration problems before starting the migration.
You do not need to stop Synapse to run this command.

```sh
mas-cli --config mas_config.yaml syn2mas --synapse-config homeserver.yaml check
```

This will either output a list of errors and warnings, or tell you that the check completed with no errors or warnings.

If you have any errors, you must resolve these before starting the migration.

If you have any warnings, please read, understand and possibly resolve them.
With that said, resolving them is not strictly required before starting the migration.

### Do a dry-run of the import to test

!!!!!!! TODO we don't have an exact dry-run mode exposed at the moment...

## Doing the migration

Having done the preparation, you can now proceed with the actual migration. Note that this will require downtime for the homeserver and is not easily reversible.

### Backup your data and configuration

As with any migration, it is important to backup your data before proceeding.

We also suggest making a backup copy of your homeserver's known good configuration,
before making any changes to enable MAS integration.

### Shutdown the homeserver

This is to ensure that no new sessions are created whilst the migration is in progress.

### Configure the homeserver to enable MAS integration

Follow the instructions in the [homeserver configuration guide](homeserver.md) to configure the homeserver to use MAS.

### Do the import

Once the homeserver has been stopped, MAS has been configured (but is not running!)
and you have a successful migration check,
run `syn2mas`'s `migrate` command.

Other than the change of command word, the syntax is exactly the same as the `check` command.

```sh
mas-cli --config mas_config.yaml syn2mas --synapse-config homeserver.yaml migrate
```

#### What to do if it goes wrong

If the migration fails with an error:

- You can either try to fix the error and make another attempt by re-running the command; or
- you can revert your homeserver configuration (so MAS integration is disabled once more)
  and abort the migration for now. In this case, you should not start MAS up.

Please report migration failures to the developers.

### Start up the homeserver

Start up the homeserver again with the new configuration.

### Start up MAS

Start up MAS.

### Update or serve the .well-known

The `.well-known/matrix/client` needs to be served as described [here](./well-known.md).
