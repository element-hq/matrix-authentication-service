// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Build script for `mas-cli`.
//!
//! This handles version detection and rustc version information:
//!
//! - `MAS_VERSION`: Explicit version override (highest priority)
//! - `MAS_GIT_VERSION`: Version from `git describe` (set automatically if git
//!   is available)
//! - Falls back to `CARGO_PKG_VERSION` if neither is available
//!
//! For rustc version, we use the `rustc_version` crate to detect it at build
//! time.

fn main() {
    // Instruct rustc that we'll be using #[cfg(tokio_unstable)]
    println!("cargo::rustc-check-cfg=cfg(tokio_unstable)");

    // Get rustc version for telemetry
    if let Ok(version) = rustc_version::version() {
        println!("cargo::rustc-env=MAS_RUSTC_VERSION={version}");
    }

    // Try to get version from git if MAS_VERSION is not set
    // We check if MAS_VERSION is set in the environment, and if not, try git
    // describe
    if std::env::var("MAS_VERSION").is_err() {
        if let Some(git_version) = git_describe() {
            println!("cargo::rustc-env=MAS_GIT_VERSION={git_version}");
        }
    }

    // Re-run if git state changes (for version detection)
    println!("cargo::rerun-if-changed=.git/HEAD");
    println!("cargo::rerun-if-changed=.git/refs/tags");
    println!("cargo::rerun-if-changed=.git/refs/heads");

    // Re-run if version env vars change
    println!("cargo::rerun-if-env-changed=MAS_VERSION");
}

/// Try to get the version from `git describe`.
///
/// Returns `None` if git is not available or the command fails.
fn git_describe() -> Option<String> {
    std::process::Command::new("git")
        .args(["describe", "--tags", "--match", "v*.*.*", "--always"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}
