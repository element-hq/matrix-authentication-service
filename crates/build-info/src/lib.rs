// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Build-time configuration for MAS.
//!
//! This crate provides compile-time constants for default paths based on the
//! build environment. Packagers can set these via environment variables at
//! build time:
//!
//! - `MAS_SHARE_DIR`: Base directory for all resources. When set, all paths
//!   default to subdirectories of this location.
//!
//! - Individual overrides (take precedence over `MAS_SHARE_DIR`):
//!   - `MAS_TEMPLATES_PATH`: Path to templates directory
//!   - `MAS_ASSETS_PATH`: Path to assets directory
//!   - `MAS_ASSETS_MANIFEST_PATH`: Path to assets manifest file
//!   - `MAS_TRANSLATIONS_PATH`: Path to translations directory
//!   - `MAS_POLICY_PATH`: Path to policy WASM module
//!
//! # Examples
//!
//! ## Dev mode (no env vars set)
//!
//! ```bash
//! cargo build
//! # templates: ./templates/
//! # assets: ./frontend/dist/
//! # manifest: ./frontend/dist/manifest.json
//! # translations: ./translations/
//! # policy: ./policies/policy.wasm
//! ```
//!
//! ## Docker build
//!
//! ```bash
//! MAS_SHARE_DIR=/usr/local/share/mas-cli cargo build
//! # templates: /usr/local/share/mas-cli/templates/
//! # assets: /usr/local/share/mas-cli/assets/
//! # manifest: /usr/local/share/mas-cli/manifest.json
//! # translations: /usr/local/share/mas-cli/translations/
//! # policy: /usr/local/share/mas-cli/policy.wasm
//! ```
//!
//! ## Dist build (pre-built binaries)
//!
//! ```bash
//! MAS_SHARE_DIR=./share cargo build
//! # templates: ./share/templates/
//! # assets: ./share/assets/
//! # manifest: ./share/manifest.json
//! # translations: ./share/translations/
//! # policy: ./share/policy.wasm
//! ```

#![deny(missing_docs, rustdoc::missing_crate_level_docs)]

// Include the generated code
include!(concat!(env!("OUT_DIR"), "/paths.rs"));
