#!/bin/sh

set -eu

# this scripts run lint and code checks
# it does not run the whole unit tests, to do it uncomment unit tests instructions

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export MAS_HOME="$(dirname "$SCRIPT_DIR")"

# fmt
cd $MAS_HOME
sh ./misc/update.sh
cargo +nightly fmt 

# unit tests
#export DATABASE_URL=postgresql://postgres:postgres@localhost:5439/postgres
#cargo test --workspace
#export DATABASE_URL=postgresql://postgres:postgres@localhost:5439/postgres; cargo test --lib views::register::password::tests::test_register

# clippy
unset DATABASE_URL
cargo clippy --workspace --tests --bins --lib -- -D warnings

# js lint
cd $MAS_HOME/frontend
npm run lint