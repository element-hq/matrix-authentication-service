# `syn2mas`

Tool to import data from an existing Synapse homeserver into MAS.

Global options:
- `--config <config>`: Path to the MAS configuration file.
- `--help`: Print help.
- `--synapse-config <synapse-config>`: Path to the Synapse configuration file.
- `--synapse-database-uri <synapse-database-uri>`: Override the Synapse database URI.

If your Synapse is configured with OIDC providers, note that you will need to
configure the `synapse_idp_id` for them for each provider in the MAS
`upstream_oauth2.providers` list. The Synapse IDP ID's can be removed after
a successful migration has been completed.

## `syn2mas check`

Check the setup for potential problems before running a migration

```console
$ mas-cli syn2mas check --config mas_config.yaml --synapse-config homeserver.yaml
```

## `syn2mas migrate [--dry-run]`

Migrate data from the homeserver to MAS.

The `--dry-run` option will perform a dry-run of the migration, which is safe to run without stopping Synapse.
It will perform a full data migration, but then empty the MAS database at the end to roll back.


```console
$ mas-cli syn2mas migrate --config mas_config.yaml --synapse-config homeserver.yaml
```
