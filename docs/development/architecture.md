# Architecture

The service is meant to be easily embeddable, with only a dependency to a database.
It is also meant to stay lightweight in terms of resource usage and easily scalable horizontally.

## Scope and goals

The Matrix Authentication Service has been created to support the migration of Matrix to an OpenID Connect (OIDC) based architecture as per [MSC3861](https://github.com/matrix-org/matrix-spec-proposals/pull/3861).

It is not intended to be a general purpose Identity Provider (IdP) and instead focuses on the specific needs of Matrix.

Furthermore, it is only intended that it would speak OIDC for authentication and not other protocols. Instead, if you want to connect to an upstream SAML, CAS or LDAP backend then you need to pair MAS with a separate service (such as [Dex](https://dexidp.io) or [Keycloak](https://www.keycloak.org)) which does that translation for you.

Whilst it only supports use with Synapse today, we hope that other homeservers will become supported in future.

If you need some other feature that MAS doesn't support (such as TOTP or WebAuthn), then you should consider pairing MAS with another IdP that does support the features you need.

## Workspace and crate split

The whole repository is a [Cargo Workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html) that includes multiple crates under the `/crates` directory.

This includes:

 - `mas-cli`: Command line utility, main entry point
 - [`mas-config`][mas-config]: Configuration parsing and loading
 - [`mas-data-model`][mas-data-model]: Models of objects that live in the database, regardless of the storage backend
 - [`mas-email`][mas-email]: High-level email sending abstraction
 - [`mas-handlers`][mas-handlers]: Main HTTP application logic
 - [`mas-iana`][mas-iana]: Auto-generated enums from IANA registries
 - [`mas-iana-codegen`][mas-iana-codegen]: Code generator for the `mas-iana` crate
 - [`mas-jose`][mas-jose]: JWT/JWS/JWE/JWK abstraction
 - [`mas-static-files`][mas-static-files]: Frontend static files (CSS/JS). Includes some frontend tooling
 - [`mas-storage`][mas-storage]: Abstraction of the storage backends
 - [`mas-storage-pg`][mas-storage-pg]: Storage backend implementation for a PostgreSQL database
 - [`mas-tasks`][mas-tasks]: Asynchronous task runner and scheduler
 - [`oauth2-types`][oauth2-types]: Useful structures and types to deal with OAuth 2.0/OpenID Connect endpoints. This might end up published as a standalone library as it can be useful in other contexts.

[mas-config]: ../rustdoc/mas_config/index.html
[mas-data-model]: ../rustdoc/mas_data_model/index.html
[mas-email]: ../rustdoc/mas_email/index.html
[mas-handlers]: ../rustdoc/mas_handlers/index.html
[mas-iana]: ../rustdoc/mas_iana/index.html
[mas-iana-codegen]: ../rustdoc/mas_iana_codegen/index.html
[mas-jose]: ../rustdoc/mas_jose/index.html
[mas-static-files]: ../rustdoc/mas_static_files/index.html
[mas-storage]: ../rustdoc/mas_storage/index.html
[mas-storage-pg]: ../rustdoc/mas_storage/index.html
[mas-tasks]: ../rustdoc/mas_tasks/index.html
[oauth2-types]: ../rustdoc/oauth2_types/index.html

## Important crates

The project makes use of a few important crates.

### Async runtime: `tokio`

[Tokio](https://tokio.rs/) is the async runtime used by the project.
The choice of runtime does not have much impact on most of the code.

It has an impact when:

 - spawning asynchronous work (as in "not awaiting on it immediately")
 - running CPU-intensive tasks. They should be ran in a blocking context using `tokio::task::spawn_blocking`. This includes password hashing and other crypto operations.
 - when dealing with shared memory, e.g. mutexes, rwlocks, etc.

### Logging: `tracing`

Logging is handled through the [`tracing`](https://docs.rs/tracing/*/tracing/) crate.
It provides a way to emit structured log messages at various levels.

```rust
use tracing::{info, debug};

info!("Logging some things");
debug!(user = "john", "Structured stuff");
```

`tracing` also provides ways to create spans to better understand where a logging message comes from.
In the future, it will help building OpenTelemetry-compatible distributed traces to help with debugging.

`tracing` is becoming the standard to log things in Rust.
By itself it will do nothing unless a subscriber is installed to -for example- log the events to the console.

The CLI installs [`tracing-subcriber`](https://docs.rs/tracing-subscriber/*/tracing_subscriber/) on startup to log in the console.
The log filter, output format (text or JSON) and destination are driven by the
[`telemetry.logging`](../reference/configuration.md#telemetry) configuration
section; the `RUST_LOG` environment variable, when set, overrides the configured
filter.

### Error management: `thiserror` / `anyhow`

[`thiserror`](https://docs.rs/thiserror/*/thiserror/) helps defining custom error types.
This is especially useful for errors that should be handled in a specific way, while being able to augment underlying errors with additional context.

[`anyhow`](https://docs.rs/anyhow/*/anyhow/) helps dealing with chains of errors.
It allows for quickly adding additional context around an error while it is being propagated.

Both crates work well together and complement each other.

### Database interactions: `sqlx`

Interactions with the database are done through [`sqlx`](https://github.com/launchbadge/sqlx), an async, pure-Rust SQL library with compile-time check of queries.
It also handles schema migrations.

### Templates: `tera`

[Tera](https://tera.netlify.app/) was chosen as template engine for its simplicity as well as its ability to load templates at runtime.
The builtin templates are embedded in the final binary through some macro magic.

The downside of Tera compared to compile-time template engines is the possibility of runtime crashes.
This can however be somewhat mitigated with unit tests.

### Crates from *RustCrypto*

The [RustCrypto team](https://github.com/RustCrypto) offer high quality, independent crates for dealing with cryptography.
The whole project is highly modular and APIs are coherent between crates.
