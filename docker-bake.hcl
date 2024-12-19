// This is what is baked by GitHub Actions
group "default" { targets = ["regular", "debug", "syn2mas"] }

// Targets filled by GitHub Actions: one for the regular tag, one for the debug tag
target "docker-metadata-action" {}
target "docker-metadata-action-debug" {}
target "docker-metadata-action-syn2mas" {}

// This sets the platforms and is further extended by GitHub Actions to set the
// output and the cache locations
target "base" {
  args = {
    // This is set so that when we use a git context, the .git directory is
    // present, as we infer the version at build time out of it
    BUILDKIT_CONTEXT_KEEP_GIT_DIR = 1
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

target "syn2mas" {
  inherits = ["base", "docker-metadata-action-syn2mas"]
  context = "./tools/syn2mas"
}
