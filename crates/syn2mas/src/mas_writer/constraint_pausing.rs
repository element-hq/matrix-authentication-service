// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use sqlx::PgConnection;
use tracing::debug;

use super::{Error, IntoDatabase};

/// Description of a constraint, which allows recreating it later.
pub struct ConstraintDescription {
    pub name: String,
    pub table_name: String,
    pub definition: String,
}

pub struct IndexDescription {
    pub name: String,
    pub table_name: String,
    pub definition: String,
}

/// Look up and return the definition of a constraint.
pub async fn describe_constraints_on_table(
    conn: &mut PgConnection,
    table_name: &str,
) -> Result<Vec<ConstraintDescription>, Error> {
    sqlx::query_as!(
        ConstraintDescription,
        r#"
            SELECT conrelid::regclass::text AS "table_name!", conname AS "name!", pg_get_constraintdef(c.oid) AS "definition!"
            FROM pg_constraint c
            JOIN pg_namespace n ON n.oid = c.connamespace
            WHERE contype IN ('f', 'p', 'u') AND conrelid::regclass::text = $1
            AND n.nspname = current_schema;
        "#,
        table_name
    ).fetch_all(&mut *conn).await.into_database_with(|| format!("could not read constraint definitions of {table_name}"))
}

/// Look up and return the definitions of foreign-key constraints whose
/// target table is the one specified.
pub async fn describe_foreign_key_constraints_to_table(
    conn: &mut PgConnection,
    target_table_name: &str,
) -> Result<Vec<ConstraintDescription>, Error> {
    sqlx::query_as!(
        ConstraintDescription,
        r#"
            SELECT conrelid::regclass::text AS "table_name!", conname AS "name!", pg_get_constraintdef(c.oid) AS "definition!"
            FROM pg_constraint c
            JOIN pg_namespace n ON n.oid = c.connamespace
            WHERE contype = 'f' AND confrelid::regclass::text = $1
            AND n.nspname = current_schema;
        "#,
        target_table_name
    ).fetch_all(&mut *conn).await.into_database_with(|| format!("could not read FK constraint definitions targetting {target_table_name}"))
}

/// Look up and return the definitions of all indices on a given table.
pub async fn describe_indices_on_table(
    conn: &mut PgConnection,
    table_name: &str,
) -> Result<Vec<IndexDescription>, Error> {
    sqlx::query_as!(
        IndexDescription,
        r#"
            SELECT indexname AS "name!", indexdef AS "definition!", schemaname AS "table_name!"
            FROM pg_indexes
            WHERE schemaname = current_schema AND tablename = $1 AND indexname IS NOT NULL AND indexdef IS NOT NULL
        "#,
        table_name
    ).fetch_all(&mut *conn).await.into_database("cannot search for indices")
}

/// Drops a constraint from the database.
///
/// The constraint must exist prior to this call.
pub async fn drop_constraint(
    conn: &mut PgConnection,
    constraint: &ConstraintDescription,
) -> Result<(), Error> {
    let name = &constraint.name;
    let table_name = &constraint.table_name;
    debug!("dropping constraint {name} on table {table_name}");
    sqlx::query(&format!("ALTER TABLE {table_name} DROP CONSTRAINT {name};"))
        .execute(&mut *conn)
        .await
        .into_database_with(|| format!("failed to drop constraint {name} on {table_name}"))?;

    Ok(())
}

/// Drops an index from the database.
///
/// The index must exist prior to this call.
pub async fn drop_index(conn: &mut PgConnection, index: &IndexDescription) -> Result<(), Error> {
    let index_name = &index.name;
    debug!("dropping index {index_name}");
    sqlx::query(&format!("DROP INDEX {index_name};"))
        .execute(&mut *conn)
        .await
        .into_database_with(|| format!("failed to temporarily drop {index_name}"))?;

    Ok(())
}

/// Restores (recreates) a constraint.
///
/// The constraint must not exist prior to this call.
pub async fn restore_constraint(
    conn: &mut PgConnection,
    constraint: &ConstraintDescription,
) -> Result<(), Error> {
    let ConstraintDescription {
        name,
        table_name,
        definition,
    } = &constraint;
    sqlx::query(&format!(
        "ALTER TABLE {table_name} ADD CONSTRAINT {name} {definition};"
    ))
    .execute(conn)
    .await
    .into_database_with(|| {
        format!("failed to recreate constraint {name} on {table_name} with {definition}")
    })?;

    Ok(())
}

/// Restores (recreates) a index.
///
/// The index must not exist prior to this call.
pub async fn restore_index(conn: &mut PgConnection, index: &IndexDescription) -> Result<(), Error> {
    let IndexDescription {
        name,
        table_name,
        definition,
    } = &index;

    sqlx::query(&format!("{definition};"))
        .execute(conn)
        .await
        .into_database_with(|| {
            format!("failed to recreate index {name} on {table_name} with {definition}")
        })?;

    Ok(())
}
