# Database

Interactions with the database goes through `sqlx`.
It provides async database operations with connection pooling, migrations support and compile-time check of queries through macros.

## Writing database interactions

All database interactions are done through repositoriy traits. Each repository trait usually manages one type of data, defined in the [`mas-data-model`][mas-data-model] crate.

Defining a new data type and associated repository looks like this:

 - Define new structs in [`mas-data-model`][mas-data-model] crate
 - Define the repository trait in [`mas-storage`][mas-storage] crate
 - Make that repository trait available via the `RepositoryAccess` trait in [`mas-storage`][mas-storage] crate
 - Setup the database schema by writing a migration file in [`mas-storage-pg`][mas-storage-pg] crate
 - Implement the new repository trait in [`mas-storage-pg`][mas-storage-pg] crate
 - Write tests for the PostgreSQL implementation in [`mas-storage-pg`][mas-storage-pg] crate

Some of those steps are documented in more details in the [`mas-storage`][mas-storage] and [`mas-storage-pg`][mas-storage-pg] crates.

[mas-data-model]: ../rustdoc/mas_data_model/index.html
[mas-storage]: ../rustdoc/mas_storage/index.html
[mas-storage-pg]: ../rustdoc/mas_storage_pg/index.html

## Compile-time check of queries

To be able to check queries, `sqlx` has to introspect the live database.
Usually it does so by having the database available at compile time, but to avoid that we're using the `offline` feature of `sqlx`, which saves the introspection informatons as a flat file in the repository.

Preparing this flat file is done through `sqlx-cli`, and should be done everytime the database schema or the queries changed.

```sh
# Install the CLI
cargo install sqlx-cli --no-default-features --features postgres

cd crates/storage-pg/ # Must be in the mas-storage-pg crate folder
export DATABASE_URL=postgresql:///matrix_auth
cargo sqlx prepare
```

## Migrations

Migration files live in the `migrations` folder in the `mas-storage-pg` crate.

```sh
cd crates/storage-pg/ # Again, in the mas-storage-pg crate folder
export DATABASE_URL=postgresql:///matrix_auth
cargo sqlx migrate run # Run pending migrations
cargo sqlx migrate add [description] # Add new migration files
```

Note that migrations are embedded in the final binary and can be run from the service CLI tool.

### Removing migrations

For various reasons, we may want to delete migrations.
In case we do, we *must* declare that migration version as allowed to be missing.
This is because on startup, MAS will validate that all the applied migrations are known, and warn if some are missing.

To do so, get the migration version and add it to the `ALLOWED_MISSING_MIGRATIONS` array in the `mas-storage-pg` crate.

### Modifying existing migrations

We may want to modify existing migrations to fix mistakes.
In case we do, we *must* save the hash of the original migration file so that MAS can validate it on startup.

To do so, extract the first 16 bytes of the existing applied migration and append it to the `ALLOWED_ALTERNATE_CHECKSUMS` array in the `mas-storage-pg` crate.

```sql
SELECT version, ENCODE(SUBSTRING(checksum FOR 16), 'hex') AS short_checksum
FROM _sqlx_migrations
WHERE version = 20250410000002;
```
```
    version     |          short_checksum
----------------+----------------------------------
 20250410000002 | f2b8f120deae27e760d079a30b77eea3
```
