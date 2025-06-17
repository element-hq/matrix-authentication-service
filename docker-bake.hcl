# Copyright 2025 New Vector Ltd.
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
# Please see LICENSE files in the repository root for full details.
#
// This is used to set the version reported by the binary through an environment
// variable. This is mainly useful when building out of a git context, like in
// CI, where we don't have the full commit history available
variable "VERGEN_GIT_DESCRIBE" {}

// This is what is baked by GitHub Actions
group "default" { targets = ["regular", "debug"] }

// Targets filled by GitHub Actions: one for the regular tag, one for the debug tag
target "docker-metadata-action" {}
target "docker-metadata-action-debug" {}

// This sets the platforms and is further extended by GitHub Actions to set the
// output and the cache locations
target "base" {
  args = {
    // This is set so that when we use a git context, the .git directory is
    // present, as we may be infering the version at build time out of it
    BUILDKIT_CONTEXT_KEEP_GIT_DIR = 1

    // Pass down the version from an external git describe source
    VERGEN_GIT_DESCRIBE = "${VERGEN_GIT_DESCRIBE}"
  }

  platforms = [
    "linux/amd64",
    "linux/arm64",
  ]
}

target "regular" {
  inherits = ["base", "docker-metadata-action"]
}

target "debug" {
  inherits = ["base", "docker-metadata-action-debug"]
  target = "debug"
}
