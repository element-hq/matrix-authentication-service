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

### Get `syn2mas`

The easiest way to get `syn2mas` is through [`npm`](https://www.npmjs.com/package/@vector-im/syn2mas):

```sh
npm install -g @vector-im/syn2mas
```

### Run the migration advisor

You can use the advisor mode of the `syn2mas` tool to identify extra configuration steps or issues with the configuration of the homeserver.

```sh
syn2mas --command=advisor --synapseConfigFile=homeserver.yaml
```

This will output `WARN` entries for any identified actions and `ERROR` entries in the case of any issues that will prevent the migration from working.

### Install and configure MAS alongside your existing homeserver

Follow the instructions in the [installation guide](installation.md) to install MAS alongside your existing homeserver.

#### Local passwords

Synapse uses bcrypt as its password hashing scheme while MAS defaults to using the newer argon2id.
You will have to configure the version 1 scheme as bcrypt for migrated passwords to work.
It is also recommended that you keep argon2id as version 2 so that once users log in, their hashes will be updated to the newer recommended scheme.
If you have set a pepper in the Synapses password_config section of your homeserver.yaml then you need to specify this pepper as the secret field for your bcrypt scheme. Otherwise logins with the correct Password will fail.

Example passwords configuration:
```yml
passwords:
  enabled: true
  schemes:
  - version: 1
    algorithm: bcrypt
    # Optional, The secret field is the equivalent to Synapses password_config pepper.
    secret: secretPepperValue
  - version: 2
    algorithm: argon2id
```

### Map any upstream SSO providers

If you are using an upstream SSO provider then you will need to provision the upstream provide in MAS manually.

Each upstream provider will need to be given as an `--upstreamProviderMapping` command line option to the import tool.

### Prepare the MAS database

Once the database is created, it still needs to have its schema created and synced with the configuration.
This can be done with the following command:

```sh
mas-cli config sync
```

### Do a dry-run of the import to test

```sh
syn2mas --command migrate --synapseConfigFile homeserver.yaml --masConfigFile config.yaml --dryRun
```

If no errors are reported then you can proceed to the next step.

## Doing the migration

Having done the preparation, you can now proceed with the actual migration. Note that this will require downtime for the homeserver and is not easily reversible.

### Backup your data

As with any migration, it is important to backup your data before proceeding.

### Shutdown the homeserver

This is to ensure that no new sessions are created whilst the migration is in progress.

### Configure the homeserver

Follow the instructions in the [homeserver configuration guide](homeserver.md) to configure the homeserver to use MAS.

### Do the import

Run `syn2mas` in non-dry-run mode.

```sh
syn2mas --command migrate --synapseConfigFile homeserver.yaml --masConfigFile config.yaml --dryRun false
```

### Start up the homeserver

Start up the homeserver again with the new configuration.

### Update or serve the .well-known

The `.well-known/matrix/client` needs to be served as described [here](./well-known.md).
