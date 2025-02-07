# `server`

Global options:
- `--config <config>`: Path to the configuration file.
- `--help`: Print help.

## `server`

Runs the authentication service.

Options:
- `--no-migrate`: Do not apply pending database migrations on start.
- `--no-worker`: Do not start the task worker.
- `--no-sync`: Do not sync the configuration with the database.

```
$ mas-cli server
INFO mas_cli::server: Starting task scheduler
INFO mas_core::templates: Loading builtin templates
INFO mas_cli::server: Listening on http://0.0.0.0:8080
```
