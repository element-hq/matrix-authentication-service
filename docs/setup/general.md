# General configuration

## Initial configuration generation

The service needs a few unique secrets and keys to work.
It mainly includes:

 - the various signing keys referenced in the [`secrets.keys`](../reference/configuration.md#secrets) section
 - the encryption key used to encrypt fields in the database and cookies, set in the [`secrets.encryption`](../reference/configuration.md#secrets) section
 - a shared secret between the service and the homeserver, set in the [`matrix.secret`](../reference/configuration.md#matrix) section

Although it is possible to generate these secrets manually, it is strongly recommended to use the [`config generate`](../reference/cli/config.md#config-generate) command to generate a configuration file with unique secrets and keys.

```sh
mas-cli config generate > config.yaml
```

If you're using the docker container, the command `mas-cli` can be invoked with `docker run`:

```sh
docker run ghcr.io/element-hq/matrix-authentication-service config generate > config.yaml
```

This applies to all of the `mas-cli` commands in this document.

**Note:** The generated configuration file is very extensive, and contains the default values for all the configuration options.
This will be made easier to read in the future, but in the meantime, it is recommended to strip untouched options from the configuration file.

## Using and inspecting the configuration file

When using the `mas-cli`, multiple configuration files can be loaded, with the following rule:

1. If the `--config` option is specified, possibly multiple times, load the file at the specified path, relative to the current working directory
2. If not, load the files specified in the `MAS_CONFIG` environment variable if set, separated by `:`, relative to the current working directory
3. If not, load the file at `config.yaml` in the current working directory

The validity of the configuration file can be checked using the [`config check`](../reference/cli/config.md#config-check) command:

```sh
# This will read both the `first.yaml` and `second.yaml` files
mas-cli config check --config=first.yaml --config=second.yaml

# This will also read both the `first.yaml` and `second.yaml` files
MAS_CONFIG=first.yaml:second.yaml mas-cli config check

# This will only read the `config.yaml` file
mas-cli config check
```

To help understand what the resulting configuration looks like after merging all the configuration files, the [`config dump`](../reference/cli/config.md#config-dump) command can be used:

```sh
mas-cli config dump
```

## Setting configuration values using environment variables

Sometimes it is not appropriate to set config values directly (e.g. when keeping the configuration stored in git) or it is easier to obtain the config value from an external source (e.g. when integrating the service in k8s).

For this reason the service fills missing configuration values from environment variables, if they adhere to the right format.
The variable must start with the prefix `MAS_` followed by the path for the values, with each component separated either by `.` or `_`.

For example a variable `MAS_database_uri` with value `postgresql://...` would be equivalent to the following config snippet:

```yaml
database:
  uri: postgresql://...
```

Just be aware, that for many config values that contain secrets there exists an equivalent version with suffix `_file` that allows reading secret values from files, which is considered more secure.

## Configuration schema

The configuration file is validated against a JSON schema, which can be found [here](../config.schema.json).
Many [tools in text editors](https://json-schema.org/implementations.html#editors) can use this schema to provide autocompletion and validation.

## Syncing the configuration file with the database

Some sections of the configuration file need to be synced every time the configuration file is updated.
This includes the [`clients`](../reference/configuration.md#clients) and [`upstream_oauth`](../reference/configuration.md#upstream-oauth) sections.
The configuration is synced by default on startup, and can be manually synced using the [`config sync`](../reference/cli/config.md#config-sync---prune---dry-run) command.

By default, this will only add new clients and upstream OAuth providers and update existing ones, but will not remove entries that were removed from the configuration file.
To do so, use the `--prune` option:

```sh
mas-cli config sync --prune
```

## Next step

After generating the configuration file, the next step is to [set up a database](./database.md).
