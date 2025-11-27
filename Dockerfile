# syntax = docker/dockerfile:1.7.1
# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.

# Builds a minimal image with the binary only. It is multi-arch capable,
# cross-building to aarch64 and x86_64. When cross-compiling, Docker sets two
# implicit BUILDARG: BUILDPLATFORM being the host platform and TARGETPLATFORM
# being the platform being built.

#:tchap:
# tchap files are added to this image (templates, translations, css)
#:tchap:

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=12
ARG DEBIAN_VERSION_NAME=bookworm
ARG RUSTC_VERSION=1.89.0
ARG NODEJS_VERSION=24.11.0
# Keep in sync with .github/actions/build-policies/action.yml and policies/Makefile
ARG OPA_VERSION=1.8.0 
ARG CARGO_AUDITABLE_VERSION=0.7.0

##########################################
## Build stage that builds the frontend ##
##########################################
FROM --platform=${BUILDPLATFORM} docker.io/library/node:${NODEJS_VERSION}-${DEBIAN_VERSION_NAME} AS frontend

WORKDIR /app/frontend

COPY ./frontend/.npmrc ./frontend/package.json ./frontend/package-lock.json /app/frontend/
# Network access: to fetch dependencies
RUN --network=default \
  npm ci

COPY ./frontend/ /app/frontend/
COPY ./templates/ /app/templates/
RUN --network=none \
  #:tchap:
  npm run build-tchap
  #:tchap:

# Move the built files
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
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS builder

ARG CARGO_AUDITABLE_VERSION
ARG RUSTC_VERSION

# Install pinned versions of cargo-auditable
# Network access: to fetch dependencies
RUN --network=default \
  cargo install --locked \
  cargo-auditable@=${CARGO_AUDITABLE_VERSION}

# Install all cross-compilation targets
# Network access: to download the targets
RUN --network=default \
  rustup target add  \
  --toolchain "${RUSTC_VERSION}" \
  x86_64-unknown-linux-gnu \
  aarch64-unknown-linux-gnu

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

# Set the working directory
WORKDIR /app

# Copy the code
COPY ./ /app
ENV SQLX_OFFLINE=true

ARG VERGEN_GIT_DESCRIBE
ENV VERGEN_GIT_DESCRIBE=${VERGEN_GIT_DESCRIBE}

# Network access: cargo auditable needs it
RUN --network=default \
  --mount=type=cache,target=/root/.cargo/registry \
  --mount=type=cache,target=/app/target \
  cargo auditable build \
    --locked \
    --release \
    --bin mas-cli \
    --no-default-features \
    --features docker \
    --target x86_64-unknown-linux-gnu \
    --target aarch64-unknown-linux-gnu \
  && mv "target/x86_64-unknown-linux-gnu/release/mas-cli" /usr/local/bin/mas-cli-amd64 \
  && mv "target/aarch64-unknown-linux-gnu/release/mas-cli" /usr/local/bin/mas-cli-arm64

#######################################
## Prepare /usr/local/share/mas-cli/ ##
#######################################
FROM --platform=${BUILDPLATFORM} scratch AS share

COPY --from=frontend /share /share
COPY --from=policy /app/policies/policy.wasm /share/policy.wasm
COPY ./templates/ /share/templates
COPY ./translations/ /share/translations

#:tchap:
COPY ./tchap/resources/templates/ /share/templates/
COPY ./tchap/resources/translations/ /share/translations/
#:tchap:


##################################
## Runtime stage, debug variant ##
##################################
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:debug-nonroot AS debug

ARG TARGETARCH
COPY --from=builder /usr/local/bin/mas-cli-${TARGETARCH} /usr/local/bin/mas-cli
COPY --from=share /share /usr/local/share/mas-cli

WORKDIR /
ENTRYPOINT ["/usr/local/bin/mas-cli"]

###################
## Runtime stage ##
###################
FROM gcr.io/distroless/cc-debian${DEBIAN_VERSION}:nonroot

ARG TARGETARCH
COPY --from=builder /usr/local/bin/mas-cli-${TARGETARCH} /usr/local/bin/mas-cli
COPY --from=share /share /usr/local/share/mas-cli

WORKDIR /
ENTRYPOINT ["/usr/local/bin/mas-cli"]
