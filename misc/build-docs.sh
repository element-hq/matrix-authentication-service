#!/bin/sh

# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
#
# This script is used by the Cloudflare Pages to build the documentation.
# It detects if it's running in the Cloudflare Pages build environment and will install the required dependencies.
# It can also be used locally to build the documentation, given that the required dependencies are installed.

set -eux

# Install the dependencies if we're in the Cloudflare Pages build environment
# In this environment, the CF_PAGES environment variable is set to 1
if [ "${CF_PAGES:-""}" = "1" ]; then
  MDBOOK_VERSION=0.4.32

  # Install rustup
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none -y

  # Source the environment variables to add cargo to the path
  . "$HOME/.cargo/env"

  # Install the minimal toolchain, which includes rustc, rustdoc, and cargo
  rustup toolchain install stable --profile minimal

  # Install mdbook
  MDBOOK_URL="https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/mdbook-v${MDBOOK_VERSION}-$(uname -m)-unknown-linux-gnu.tar.gz"
  curl --proto '=https' --tlsv1.2 -sSfL "${MDBOOK_URL}" | tar -C "$HOME/.cargo/bin" -xzv
fi

# Sanity check
rustdoc --version
rustc --version
cargo --version
mdbook --version
npx --version

# Build the docs
mdbook build

# Build the rustdoc
# This is required to be able to use the unstable `-Zrustdoc-map` flag
env RUSTC_BOOTSTRAP=1 \
  cargo doc -Zrustdoc-map --workspace --lib --no-deps
# Delete the rustdoc lockfile
rm target/doc/.lock

# Move the Rust documentation within the mdBook
rm -rf target/book/rustdoc
mv target/doc target/book/rustdoc

# Build the frontend storybook
cd frontend
npm ci
npx storybook build -o ../target/book/storybook
cd ..
