# `config`

Helps to deal with the configuration

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `config check`

Check the validity of configuration files.

```console
$ mas-cli config check --config=config.yaml
INFO mas_cli::config: Configuration file looks good path=["config.yaml"]
```

## `config dump`

Dump the merged configuration tree.

```console
$ mas-cli config dump --config=first.yaml --config=second.yaml
---
clients:
  # ...
```

## `config generate`

Generate a sample configuration file.
It generates random signing keys (`.secrets.keys`) and the cookie encryption secret (`.secrets.encryption`).

```console
$ mas-cli config generate > config.yaml
INFO generate: mas_config::oauth2: Generating keys...
INFO generate:rsa: mas_config::oauth2: Done generating RSA key
INFO generate:ecdsa: mas_config::oauth2: Done generating ECDSA key
```

## `config sync [--prune] [--dry-run]`

Synchronize the configuration with the database.
This will synchronize the `clients` and `upstream_oauth` sections of the configuration with the database.
By default, it does not delete clients and upstreams that are not in the configuration anymore. Use the `--prune` option to do so.
The `--dry-run` option will log the changes that would be made, without actually making them.

```console
$ mas-cli config sync --prune --config=config.yaml
INFO cli.config.sync: Syncing providers and clients defined in config to database prune=true dry_run=false
INFO cli.config.sync: Updating provider provider.id=01H3FDH2XZJS8ADKRGWM84PZTY
INFO cli.config.sync: Adding provider provider.id=01H3FDH2XZJS8ADKRGWM84PZTF
INFO cli.config.sync: Deleting client client.id=01GFWRB9MYE0QYK60NZP2YF905
INFO cli.config.sync: Updating client client.id=01GFWRB9MYE0QYK60NZP2YF904
```