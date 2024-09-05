# Installation

## Pre-built binaries

Pre-built binaries can be found attached on each release, for Linux on both `x86_64` and `aarch64` architectures.

- [`mas-cli-aarch64-linux.tar.gz`](https://github.com/element-hq/matrix-authentication-service/releases/latest/download/mas-cli-aarch64-linux.tar.gz)
- [`mas-cli-x86_64-linux.tar.gz`](https://github.com/element-hq/matrix-authentication-service/releases/latest/download/mas-cli-x86_64-linux.tar.gz)

Each archive contains:

- the `mas-cli` binary
- assets needed for running the service, including:
  - `share/assets/`: the built frontend assets
  - `share/manifest.json`: the manifest for the frontend assets
  - `share/policy.wasm`: the built OPA policies
  - `share/templates/`: the default templates
  - `share/translations/`: the default translations

The location of all these assets can be overridden in the [configuration file](./configuration.md).

---

Example shell commands to download and extract the `mas-cli` binary:

```sh
ARCH=x86_64 # or aarch64
OS=linux
VERSION=latest # or a specific version, like "v0.1.0"

# URL to the right archive
URL="https://github.com/element-hq/matrix-authentication-service/releases/${VERSION}/download/mas-cli-${ARCH}-${OS}.tar.gz"

# Create a directory and extract the archive in it
mkdir -p /path/to/mas
curl -sL "$URL" | tar xzC /path/to/mas

# This should display the help message
/path/to/mas/mas-cli --help
```


## Using the Docker image

A pre-built Docker image is available here: [`ghcr.io/element-hq/matrix-authentication-service:latest`](https://ghcr.io/element-hq/matrix-authentication-service:latest)

The `latest` tag is built using the latest release.
The `main` tag is built from the `main` branch, and each commit on the `main` branch is also tagged with a stable `sha-<commit sha>` tag.

The image can also be built from the source:

1. Get the source
   ```sh
   git clone https://github.com/element-hq/matrix-authentication-service.git
   cd matrix-authentication-service
   ```
1. Build the image
   ```sh
   docker build -t mas .
   ```

## Building from the source

Building from the source requires:

- The latest stable [Rust toolchain](https://www.rust-lang.org/learn/get-started)
- [Node.js (18 and later)](https://nodejs.org/en/) and [npm](https://www.npmjs.com/get-npm)
- the [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/#running-opa) binary (or alternatively, Docker)

1. Get the source
   ```sh
   git clone https://github.com/element-hq/matrix-authentication-service.git
   cd matrix-authentication-service
   ```
1. Build the frontend
   ```sh
   cd frontend
   npm ci
   npm run build
   cd ..
   ```
   This will produce a `frontend/dist` directory containing the built frontend assets.
   This folder, along with the `frontend/dist/manifest.json` file, can be relocated, as long as the configuration file is updated accordingly.
1. Build the Open Policy Agent policies
   ```sh
   cd policies
   make
   cd ..
   ```
   OR, if you don't have `opa` installed and want to build through the OPA docker image
   ```sh
   cd policies
   make DOCKER=1
   cd ..
   ```
   This will produce a `policies/policy.wasm` file containing the built OPA policies.
   This file can be relocated, as long as the configuration file is updated accordingly.
1. Compile the CLI
   ```sh
   cargo build --release
   ```
1. Grab the built binary
   ```sh
   cp ./target/release/mas-cli ~/.local/bin # Copy the binary somewhere in $PATH
   mas-cli --help # Should display the help message
   ```

## Next steps

The service needs some configuration to work.
This includes random, private keys and secrets.
Follow the [configuration guide](./general.md) to configure the service.
