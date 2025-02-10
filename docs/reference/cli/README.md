# Command line tool

The command line interface provides subcommands that helps running the service.

## Logging

The overall log level of the CLI can be changed via the `RUST_LOG` environment variable.
Default log level is `info`.
Valid levels from least to most verbose are `error`, `warn`, `info`, `debug` and `trace`.

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
