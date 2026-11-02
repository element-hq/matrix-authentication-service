#!/bin/sh
# Copyright 2025, 2026 Element Creations Ltd.
# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
#
# Regenerates the `.sqlx` offline data. Arguments are passed to
# `cargo sqlx prepare`, e.g. `--check`.
set -eu

: "${DATABASE_URL:?You need to set DATABASE_URL}"
: "${SYN2MAS_DATABASE_URL:?You need to set SYN2MAS_DATABASE_URL}"

if [ "$DATABASE_URL" = "$SYN2MAS_DATABASE_URL" ]; then
  echo "SYN2MAS_DATABASE_URL must point to a different database than DATABASE_URL" >&2
  exit 1
fi

cd "$(dirname "$(realpath "$0")")/.."

for url in "$DATABASE_URL" "$SYN2MAS_DATABASE_URL"; do
  cargo sqlx migrate run --source crates/storage-pg/migrations --database-url "$url"
done

# Rename the MAS tables the way syn2mas does while it runs
syn2mas_sql=crates/syn2mas/src/mas_writer
psql --dbname="$SYN2MAS_DATABASE_URL" --single-transaction --file="$syn2mas_sql/syn2mas_temporary_tables.sql"
trap 'psql --dbname="$SYN2MAS_DATABASE_URL" --single-transaction --file="$syn2mas_sql/syn2mas_revert_temporary_tables.sql"' EXIT

cargo sqlx prepare --workspace "$@"
