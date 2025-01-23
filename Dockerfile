# syntax = docker/dockerfile:1.7.1

# Builds a minimal image with the binary only. It is multi-arch capable,
# cross-building to aarch64 and x86_64. When cross-compiling, Docker sets two
# implicit BUILDARG: BUILDPLATFORM being the host platform and TARGETPLATFORM
# being the platform being built.

# The Debian version and version name must be in sync
ARG DEBIAN_VERSION=12
ARG DEBIAN_VERSION_NAME=bookworm
ARG RUSTC_VERSION=1.84.0
ARG NODEJS_VERSION=20.15.0
ARG OPA_VERSION=0.64.1
ARG CARGO_AUDITABLE_VERSION=0.6.6
ARG CARGO_CHEF_VERSION=0.1.68

##########################################
## Build stage that builds the frontend ##
##########################################
FROM --platform=${BUILDPLATFORM} docker.io/library/node:${NODEJS_VERSION}-${DEBIAN_VERSION_NAME} AS frontend

WORKDIR /app/frontend

COPY ./frontend/package.json ./frontend/package-lock.json /app/frontend/
# Network access: to fetch dependencies
RUN --network=default \
  npm ci

COPY ./frontend/ /app/frontend/
COPY ./templates/ /app/templates/
RUN --network=none \
  npm run build

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

##########################################################################
## Base image with cargo-chef and the right cross-compilation toolchain ##
##########################################################################
FROM --platform=${BUILDPLATFORM} docker.io/library/rust:${RUSTC_VERSION}-${DEBIAN_VERSION_NAME} AS toolchain

ARG CARGO_AUDITABLE_VERSION
ARG CARGO_CHEF_VERSION
ARG RUSTC_VERSION

# Make cargo use the git cli for fetching dependencies
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# Install pinned versions of cargo-chef and cargo-auditable
# Network access: to fetch dependencies
RUN --network=default \
  cargo install --locked \
  cargo-chef@=${CARGO_CHEF_VERSION} \
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

#####################################
## Run the planner from cargo-chef ##
#####################################
FROM --platform=${BUILDPLATFORM} toolchain AS planner
COPY ./Cargo.toml ./Cargo.lock /app/
COPY ./crates /app/crates
RUN --network=none \
  cargo chef prepare --recipe-path recipe.json --bin crates/cli

########################
## Actual build stage ##
########################
FROM --platform=${BUILDPLATFORM} toolchain AS builder

# Build dependencies
COPY --from=planner /app/recipe.json recipe.json
# Network access: cargo-chef cook fetches the dependencies
RUN --network=default \
  cargo chef cook \
  --bin mas-cli \
  --release \
  --recipe-path recipe.json \
  --no-default-features \
  --features docker \
  --target x86_64-unknown-linux-gnu \
  --target aarch64-unknown-linux-gnu \
  --package mas-cli

# Build the rest
COPY ./ /app
ENV SQLX_OFFLINE=true
# Network access: cargo auditable needs it
RUN --network=default \
  cargo auditable build \
  --locked \
  --release \
  --bin mas-cli \
  --no-default-features \
  --features docker \
  --target x86_64-unknown-linux-gnu \
  --target aarch64-unknown-linux-gnu

# Move the binary to avoid having to guess its name in the next stage
RUN --network=none \
  mv "target/x86_64-unknown-linux-gnu/release/mas-cli" /usr/local/bin/mas-cli-amd64
RUN --network=none \
  mv "target/aarch64-unknown-linux-gnu/release/mas-cli" /usr/local/bin/mas-cli-arm64

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
