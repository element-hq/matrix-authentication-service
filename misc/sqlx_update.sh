#!/bin/sh
# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
#
set -eu

if [ "${DATABASE_URL+defined}" != defined ]; then
  echo "You need to set DATABASE_URL"
  exit 1
fi

if [ "$DATABASE_URL" = "postgres:" ]; then
  # Hacky, but psql doesn't accept `postgres:` on its own like sqlx does
  export DATABASE_URL="postgres:///"
fi

crates_dir=$(dirname $(realpath $0))"/../crates"

CRATES_WITH_SQLX="storage-pg syn2mas"

for crate in $CRATES_WITH_SQLX; do
  echo "=== Updating sqlx query info for $crate ==="

  if [ $crate = syn2mas ]; then
    # We need to apply the syn2mas_temporary_tables.sql one-off 'migration'
    # for checking the syn2mas queries

    # not evident from the help text, but psql accepts connection URLs as the dbname
    psql --dbname="$DATABASE_URL" --single-transaction --file="${crates_dir}/syn2mas/src/mas_writer/syn2mas_temporary_tables.sql"
  fi

  (cd "$crates_dir/$crate" && cargo sqlx prepare) || echo "(failed to prepare for $crate)"

  if [ $crate = syn2mas ]; then
    # Revert syn2mas temporary tables
    psql --dbname="$DATABASE_URL" --single-transaction --file="${crates_dir}/syn2mas/src/mas_writer/syn2mas_revert_temporary_tables.sql"
  fi
done
