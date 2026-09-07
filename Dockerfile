# syntax = docker/dockerfile:1.21.0
# Copyright 2025, 2026 Element Creations Ltd.
# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

# Builds a minimal image with the binary only. It is multi-arch capable,
# cross-building to aarch64 or x86_64. When cross-compiling, Docker sets two
# implicit BUILDARG: BUILDPLATFORM being the host platform and TARGETPLATFORM
# being the platform being built. Each architecture is built separately.

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=13
ARG DEBIAN_VERSION_NAME=trixie
ARG RUSTUP_VERSION=1.29.0
# Keep in sync with .node-version
ARG NODEJS_VERSION=24.15.0
# Keep in sync with .github/actions/build-policies/action.yml and policies/Makefile
ARG OPA_VERSION=1.13.1
ARG CARGO_AUDITABLE_VERSION=0.7.2

##########################################
## Build stage that builds the frontend ##
##########################################
FROM --platform=${BUILDPLATFORM} docker.io/library/node:${NODEJS_VERSION}-${DEBIAN_VERSION_NAME} AS frontend

WORKDIR /app

# Enable corepack so the pnpm version pinned in package.json's `packageManager`
# field is used.
RUN --network=default \
  corepack enable

# Copy the workspace manifest and lockfile first so the install layer can be
# cached independently from the rest of the frontend source.
COPY ./package.json ./pnpm-workspace.yaml ./pnpm-lock.yaml /app/
COPY ./frontend/package.json /app/frontend/

# Network access: to fetch dependencies
RUN --network=default \
  pnpm install --frozen-lockfile

COPY ./frontend/ /app/frontend/
COPY ./templates/ /app/templates/
RUN --network=none \
  pnpm --filter mas-frontend run build

# Move the built files
WORKDIR /app/frontend
RUN --network=none \
  mkdir -p /share/assets && \
  cp ./dist/manifest.json /share/manifest.json && \
  rm -f ./dist/index.html* ./dist/manifest.json* && \
  cp ./dist/* /share/assets/

##############################################
## Build stage that builds the OPA policies ##
##############################################
FROM --platform=${BUILDPLATFORM} docker.io/library/buildpack-deps:${DEBIAN_VERSION_NAME} AS policy

ARG BUILDOS
ARG BUILDARCH
ARG OPA_VERSION

# Download Open Policy Agent
ADD --chmod=755 https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_${BUILDOS}_${BUILDARCH}_static /usr/local/bin/opa

WORKDIR /app/policies
COPY ./policies /app/policies
RUN --network=none  \
  make -B && \
  chmod a+r ./policy.wasm

########################################
## Build stage that builds the binary ##
########################################
FROM --platform=${BUILDPLATFORM} docker.io/library/buildpack-deps:${DEBIAN_VERSION_NAME} AS builder

ARG BUILDARCH
ARG CARGO_AUDITABLE_VERSION
ARG RUSTUP_VERSION

ENV RUSTUP_HOME=/usr/local/rustup \
  CARGO_HOME=/usr/local/cargo \
  PATH=/usr/local/cargo/bin:$PATH

# Checksums come from https://static.rust-lang.org/rustup/archive/<version>/<triple>/rustup-init.sha256
# Network access: to download rustup
RUN --network=default \
  case "${BUILDARCH}" in \
    amd64) RUSTUP_TRIPLE="x86_64-unknown-linux-gnu"; RUSTUP_SHA256="4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10" ;; \
    arm64) RUSTUP_TRIPLE="aarch64-unknown-linux-gnu"; RUSTUP_SHA256="9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792" ;; \
    *) echo "unsupported architecture: ${BUILDARCH}" >&2; exit 1 ;; \
  esac && \
  curl -fsSLo rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_TRIPLE}/rustup-init" && \
  echo "${RUSTUP_SHA256} *rustup-init" | sha256sum -c - && \
  chmod +x rustup-init && \
  ./rustup-init -y --no-modify-path --default-toolchain none && \
  rm rustup-init

# Set the working directory
WORKDIR /app

# Copied on its own so the toolchain layer is cached independently of the source tree
COPY rust-toolchain.toml ./

# Network access: to download the toolchain and the cross-compilation targets
RUN --network=default \
  rustup toolchain install && \
  rustup target add \
  x86_64-unknown-linux-gnu \
  aarch64-unknown-linux-gnu

# Install pinned versions of cargo-auditable
# Network access: to fetch dependencies
RUN --network=default \
  cargo install --locked \
  cargo-auditable@=${CARGO_AUDITABLE_VERSION}

RUN --network=none \
  dpkg --add-architecture arm64 && \
  dpkg --add-architecture amd64

ARG BUILDPLATFORM

# Install cross-compilation toolchains for all supported targets
# Network access: to install apt packages
RUN --network=default \
  apt-get update && apt-get install -y \
  $(if [ "${BUILDPLATFORM}" != "linux/arm64" ]; then echo "g++-aarch64-linux-gnu"; fi) \
  $(if [ "${BUILDPLATFORM}" != "linux/amd64" ]; then echo "g++-x86-64-linux-gnu"; fi) \
  libc6-dev-amd64-cross \
  libc6-dev-arm64-cross \
  g++

# Setup the cross-compilation environment
ENV \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
  CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
  CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
  CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++

# Copy the code
COPY ./ /app
ENV SQLX_OFFLINE=true

ARG VERGEN_GIT_DESCRIBE
ENV VERGEN_GIT_DESCRIBE=${VERGEN_GIT_DESCRIBE}

ARG TARGETARCH

# Network access: cargo auditable needs it
RUN --network=default \
  --mount=type=cache,target=/usr/local/cargo/registry \
  --mount=type=cache,target=/app/target \
  RUST_TARGET=$(case "${TARGETARCH}" in \
    amd64) echo "x86_64-unknown-linux-gnu" ;; \
    arm64) echo "aarch64-unknown-linux-gnu" ;; \
    *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
  esac) && \
  cargo auditable build \
    --locked \
    --release \
    --bin mas-cli \
    --no-default-features \
    --features docker \
    --target "${RUST_TARGET}" \
  && mv "target/${RUST_TARGET}/release/mas-cli" /usr/local/bin/mas-cli

#######################################
## Prepare /usr/local/share/mas-cli/ ##
#######################################
FROM --platform=${BUILDPLATFORM} scratch AS share

COPY --from=frontend /share /share
COPY --from=policy /app/policies/policy.wasm /share/policy.wasm
COPY ./templates/ /share/templates
COPY ./translations/ /share/translations

##################################
## Runtime stage, debug variant ##
##################################
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:debug-nonroot AS debug

COPY --from=builder /usr/local/bin/mas-cli /usr/local/bin/mas-cli
COPY --from=share /share /usr/local/share/mas-cli

WORKDIR /
ENTRYPOINT ["/usr/local/bin/mas-cli"]

###################
## Runtime stage ##
###################
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:nonroot

COPY --from=builder /usr/local/bin/mas-cli /usr/local/bin/mas-cli
COPY --from=share /share /usr/local/share/mas-cli

WORKDIR /
ENTRYPOINT ["/usr/local/bin/mas-cli"]
