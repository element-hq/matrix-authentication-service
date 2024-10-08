#!/bin/sh

crates_dir=$(dirname $(realpath $0))"/../crates"

CRATES_WITH_SQLX="storage-pg syn2mas"

for crate in $CRATES_WITH_SQLX; do
  echo "=== Updating sqlx query info for $crate ==="
  (cd "$crates_dir/$crate" && cargo sqlx prepare)
done
