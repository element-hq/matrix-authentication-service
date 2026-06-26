# Command line tool

The command line interface provides subcommands that helps running the service.

## Logging

The log filter can be set either in the configuration file, under
[`telemetry.logging`](../configuration.md#telemetry), or via the `RUST_LOG`
environment variable. When `RUST_LOG` is set, it takes precedence over the
configuration file.

Default log level is `info`.
Valid levels from least to most verbose are `error`, `warn`, `info`, `debug` and `trace`.
The filter also accepts per-module directives, e.g. `info,mas_handlers=debug`.

The [`telemetry.logging`](../configuration.md#telemetry) configuration section
additionally allows switching the output format to structured JSON
(`format: json`), controlling ANSI colors (`color`), and choosing whether logs
are written to `stderr` (the default) or `stdout` (`output`).

## Global flags

### `--config`

Sets the configuration file to load.
It can be repeated multiple times to merge multiple files together.

### `--help`

Print out help instructions.

### `--version` 

Print the mas cli version.

---

```
Usage: mas-cli [OPTIONS] [COMMAND]

Commands:
  config     Configuration-related commands
  database   Manage the database
  server     Runs the web server
  worker     Run the worker
  manage     Manage the instance
  templates  Templates-related commands
  doctor     Run diagnostics on the deployment
  help       Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>  Path to the configuration file
  -h, --help             Print help
  -V, --version          Print version
```
